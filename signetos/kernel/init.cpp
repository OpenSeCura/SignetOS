/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * init.cpp - SignetOS Kernel Bootstrap for the `init` Compartment
 *
 * All boot compartment code lives in `boot/` and is compiled
 * into standalone compartment binaries embedded via `kernel/boot_images.S`.
 */

#include <signetos/compartment.hpp>
#include <signetos/init.hpp>
#include <signetos/inspect.hpp>
#include <signetos/platform.hpp>
#include <signetos/quota.hpp>
#include <signetos/sealing.hpp>
#include <signetos/sentry.hpp>
#include <signetos/syscall.hpp>
#include <signetos/thread.hpp>
#include <signetos/trap.hpp>
#include <signetos/uart.hpp>
#include <signetos/vm.hpp>

extern "C" {
extern const uint8_t _boot_img_init[];
extern const uint8_t _boot_img_uart[];
extern const uint8_t _boot_img_blk[];
extern const uint8_t _boot_img_loader[];
extern const uint8_t _boot_img_fs[];
}

namespace signetos::init {
namespace {

// Derives a read-only capability to an embedded boot image in
// `.rodata.boot_images` (bounded by `__cap_relocs` using the ELF `.size`
// emitted by `BOOT_IMAGE` in `boot_images.S`). The images are page-aligned
// and page-padded so those bounds are exact; an image whose cursor is not
// its base would make `image_install` read past it, and is refused here.
Capability boot_image_cap(const uint8_t* img_sym) {
  Capability img = reinterpret_cast<Capability>(const_cast<uint8_t*>(img_sym));
  if (!capability_is_valid(img) ||
      capability_get_address(img) != capability_get_base(img) ||
      capability_get_length(img) < sizeof(CompartmentImageHeader)) {
    return nullptr;
  }
  return capability_and_perms(img, perms::ReadOnly);
}

// Loads a standalone compartment image (`img_cap`) into `target_comp` funded
// by `target_quota` and mints its `OType::EntryPoint` (`CT = 12`) sentry.
// Same steps as `user::load_compartment_image`, but calling the kernel
// entry points directly instead of through syscall gates.
Capability load_image_kernel(Capability target_comp, Capability target_quota,
                             Capability img_cap, Status* out_status) {
  const CompartmentImageHeader* hdr = image_header(img_cap);
  if (hdr == nullptr) {
    return fail_with(out_status, Status::InvalidCapability);
  }

  Capability code_mem = compartment::allocate(
      target_comp, target_quota, image_alloc_size(hdr, img_cap), FLAG_ZERO);
  if (!capability_is_valid(code_mem)) {
    return fail_with(out_status, Status::CodeAllocFailed);
  }

  image_install(code_mem, img_cap, hdr);

  // Entry (and so the compartment's `pcc`) covers `[0, got_end)` only.
  Capability code = image_code_window(code_mem, hdr);
  if (!capability_is_valid(code)) {
    return fail_with(out_status, Status::InvalidCapability);
  }

  Capability entry = sentry::create(target_comp, code, perms::CodeRx, nullptr);
  if (!capability_is_valid(entry)) {
    return fail_with(out_status, Status::SentryFailed);
  }

  *out_status = Status::Ok;
  return entry;
}

}  // namespace

Status launch(Capability system_quota, Capability thread_quota,
              Capability* out_init_comp) {
  if (out_init_comp != nullptr) {
    *out_init_comp = nullptr;
  }
  if (!sealing::is_sealed_as(OType::QuotaVm, system_quota) ||
      !sealing::is_sealed_as(OType::QuotaThreadMem, thread_quota)) {
    return Status::InvalidCapability;
  }

  uart::print_cap("system quota", system_quota);
  uart::print_cap("thread quota", thread_quota);

  alignas(sizeof(Capability)) static Capability init_seeds[INIT_SEED_COUNT];
  size_t idx = 0;
  for (size_t i = 0; i < syscall::kSyscallCount; ++i) {
    init_seeds[idx++] = syscall::gate(static_cast<syscall::Id>(i));
    uart::print_cap("syscall", syscall::gate(static_cast<syscall::Id>(i)));
  }
  for (uint64_t i = 0; i < trap::MAX_INTERRUPT_VECTORS; ++i) {
    init_seeds[idx++] = trap::irq_authority(i);
    uart::print_cap("irq auth", trap::irq_authority(i));
  }
  for (uint64_t i = 0; i < trap::MAX_EXCEPTION_VECTORS; ++i) {
    init_seeds[idx++] = trap::exception_authority(i);
    uart::print_cap("exception auth", trap::exception_authority(i));
  }
  init_seeds[idx++] = thread_quota;

  // Check the init seed table: these kernel-minted authorities
  // are written straight into `init`'s capability table.
  for (size_t i = 0; i < INIT_SEED_COUNT; ++i) {
    inspect::assert_user_capability(init_seeds[i], "init::launch:seed");
    uart::print_cap("init seed", init_seeds[i]);
  }

  Capability seed_cap = reinterpret_cast<Capability>(&init_seeds[0]);
  seed_cap = capability_set_bounds(seed_cap, sizeof(init_seeds));

  // 2. Create the `init` compartment funded by `system_quota`.
  compartment::Status comp_status = compartment::Status::Ok;
  Capability init_comp =
      compartment::create(system_quota, seed_cap, &comp_status);
  for (size_t i = 0; i < INIT_SEED_COUNT; ++i) {
    init_seeds[i] = nullptr;
  }
  if (comp_status != compartment::Status::Ok ||
      !capability_is_valid(init_comp)) {
    return Status::CompartmentCreateFailed;
  }

  // 3. Load the standalone `user/init.bin` image into `init_comp` and mint its
  //    entry sentry.
  Capability init_img = boot_image_cap(_boot_img_init);
  Status load_status = Status::Ok;
  Capability init_sentry =
      load_image_kernel(init_comp, system_quota, init_img, &load_status);
  uart::print_cap("init sentry", init_sentry);
  if (load_status != Status::Ok || !capability_is_valid(init_sentry)) {
    compartment::destroy(init_comp);
    return load_status;
  }

  // 4. Populate the read-only `BootManifest` passed to `init` in `ca0`
  //    (`initial_arg`): a copy of the device tree, one window over the whole
  //    device range, and read-only capabilities to each embedded service
  //    binary. Manifest and DTB copy share one allocation in `init`'s own
  //    memory (page 0 is the manifest, the DTB follows), never a kernel
  //    stack; it is given back to `system_quota` once `init` has exited.
  const uint64_t dtb_bytes = platform::dtb_bytes();
  const size_t dtb_pages = (dtb_bytes + vm::PAGE_SIZE - 1) / vm::PAGE_SIZE;
  const size_t manifest_bytes = vm::PAGE_SIZE * (1 + dtb_pages);
  compartment::Status m_status = compartment::Status::Ok;
  Capability manifest_mem = compartment::allocate(
      init_comp, system_quota, manifest_bytes, FLAG_ZERO, &m_status);
  if (m_status != compartment::Status::Ok ||
      !capability_is_valid(manifest_mem)) {
    compartment::destroy(init_comp);
    return Status::CodeAllocFailed;
  }
  BootManifest& manifest = *reinterpret_cast<BootManifest*>(manifest_mem);
  manifest.dtb = nullptr;
  if (dtb_bytes != 0) {
    Capability src = vm::phys_view(platform::dtb_base(), dtb_bytes);
    if (capability_is_valid(src)) {
      Capability dst = capability_set_address(
          manifest_mem, capability_get_address(manifest_mem) + vm::PAGE_SIZE);
      dst = capability_set_bounds(dst, dtb_bytes);
      const uint8_t* s = reinterpret_cast<const uint8_t*>(src);
      uint8_t* d = reinterpret_cast<uint8_t*>(dst);
      for (uint64_t i = 0; i < dtb_bytes; ++i) {
        d[i] = s[i];
      }
      manifest.dtb = capability_and_perms(dst, perms::Load);
    }
  }
  manifest.mmio = vm::device_window(0, vm::GIGAPAGE_SIZE);
  manifest.uart_img = boot_image_cap(_boot_img_uart);
  manifest.blk_img = boot_image_cap(_boot_img_blk);
  manifest.loader_img = boot_image_cap(_boot_img_loader);
  manifest.fs_img = boot_image_cap(_boot_img_fs);

  {
    const auto* caps = reinterpret_cast<const Capability*>(&manifest);
    for (size_t i = 0; i < sizeof(manifest) / sizeof(Capability); ++i) {
      inspect::assert_user_capability(caps[i], "init::launch:manifest");
    }
  }

  Capability manifest_cap =
      capability_set_bounds(manifest_mem, sizeof(manifest));
  manifest_cap = capability_and_perms(
      manifest_cap, perms::Load | perms::LoadCapability | perms::LoadMutable);
  uart::print_cap("manifest cap", manifest_cap);
  inspect::assert_user_capability(manifest_cap, "init::launch:manifest_cap");

  // 5. Create and dispatch the initial `init` thread on `thread_quota`.
  thread::Status t_status = thread::Status::Ok;
  Capability init_thread = thread::create(thread_quota, INIT_STACK_SIZE,
                                          init_sentry, manifest_cap, &t_status);
  uart::print_cap("init thread", init_thread);
  if (t_status != thread::Status::Ok || !capability_is_valid(init_thread)) {
    compartment::destroy(init_comp);
    return Status::ThreadCreateFailed;
  }

  t_status = thread::dispatch(init_thread);
  if (t_status != thread::Status::Ok) {
    thread::kill(init_thread);
    compartment::destroy(init_comp);
    return Status::DispatchFailed;
  }

  // `init` has exited. The manifest (and with it the whole-device MMIO window
  // and the DTB copy) has served its purpose; give the pages back.
  compartment::deallocate(init_comp, system_quota, manifest_mem);

  if (out_init_comp != nullptr) {
    *out_init_comp = init_comp;
  }

  // 6. The host context is the dispatch driver. `init` may have left the
  //    scheduler's `run` entry point in `RW_SLOT_SCHED_RUN`; if so, create its
  //    thread and keep re-dispatching it. Every `sys_thread_exit` unwinds to
  //    this loop (`thread::exit` always returns to the host), and
  //    re-dispatching `sched_thread` resumes it inside the `sys_thread_switch`
  //    that ran the thread which just exited, so the scheduler learns about
  //    every exit without any extra syscall. The loop ends when the
  //    scheduler thread itself exits.
  Capability init_table = compartment::table_writable(init_comp);
  Capability sched_run = nullptr;
  if (capability_is_valid(init_table)) {
    sched_run = reinterpret_cast<Capability*>(init_table)[RW_SLOT_SCHED_RUN];
  }
  if (!sealing::is_sealed_as(OType::EntryPoint, sched_run)) {
    return Status::Ok;
  }
  Capability sched_thread = thread::create(thread_quota, SCHED_RUN_STACK_SIZE,
                                           sched_run, nullptr, &t_status);
  if (t_status != thread::Status::Ok || !capability_is_valid(sched_thread)) {
    return Status::ThreadCreateFailed;
  }
  for (;;) {
    t_status = thread::dispatch(sched_thread);
    if (t_status != thread::Status::Ok) {
      // `InvalidCapability` here means the scheduler thread has exited.
      break;
    }
  }
  return Status::Ok;
}

}  // namespace signetos::init
