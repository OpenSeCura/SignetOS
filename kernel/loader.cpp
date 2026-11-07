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
 * loader.cpp - Installing the loader, and giving a compartment its loader
 *
 * See loader.hpp. The loader itself is `boot/loader.cpp`.
 */

#include <signetos/loader.hpp>

#include <signetos/compartment.hpp>
#include <signetos/debug/inspect.hpp>
#include <signetos/debug/report.hpp>
#include <signetos/init.hpp>
#include <signetos/quota.hpp>
#include <signetos/sentry.hpp>
#include <signetos/syscall.hpp>
#include <signetos/vm.hpp>

extern "C" {
extern const uint8_t _boot_img_loader[];  // kernel/boot_images.S
}

namespace signetos::loader {
namespace {

// The loader's code: `CodeRx`, at the start of its image, which is where a
// compartment image is entered (user/entry.S). Set once by `init`.
Capability s_code = nullptr;

}  // namespace

void init(Capability system_quota) {
  const Capability image = capability_and_perms(
      reinterpret_cast<Capability>(const_cast<uint8_t*>(_boot_img_loader)),
      perms::ReadOnly);
  const init::CompartmentImageHeader* hdr = init::image_header(image);
  if (hdr == nullptr) {
    debug::panic("loader: the embedded loader is not a compartment image");
  }
  // Every compartment runs this one copy, so it must have nothing to write:
  // its image ends with its `.got`, with no `.data` or `.bss` after it.
  if (hdr->bss_end > hdr->got_end) {
    debug::panic("loader: the loader image has .data or .bss");
  }

  const size_t pages =
      (init::image_alloc_size(hdr, image) + vm::PAGE_SIZE - 1) / vm::PAGE_SIZE;
  if (quota::charge(system_quota, pages * vm::PAGE_SIZE) != Status::Ok) {
    debug::panic("loader: no memory for the loader");
  }
  const Capability memory = vm::alloc_pages(pages);
  if (!capability_is_valid(memory)) {
    debug::panic("loader: no memory for the loader");
  }
  init::image_install(memory, image, hdr);
  __asm__ volatile("fence.i" ::: "memory");

  // Nor may it reach anything writable: every capability its relocations
  // left in it must be read-only. (A relocation to the end of the image, say,
  // would otherwise hand every compartment a writable view of this copy.)
  const Capability* words = reinterpret_cast<const Capability*>(memory);
  for (size_t i = 0; i < pages * vm::PAGE_SIZE / sizeof(Capability); ++i) {
    if (capability_is_valid(words[i]) &&
        capability_has_perms(words[i], perms::Store)) {
      debug::panic("loader: the loader image holds a writable capability");
    }
  }

  // Only this code capability is kept. `memory`, the one capability that
  // could write the loader, goes out of scope here.
  s_code = sentry::entry_code(init::image_code_window(memory, hdr));
  if (!capability_is_valid(s_code)) {
    debug::panic("loader: cannot make the loader's code capability");
  }
}

Capability prepare(Capability comp, Capability mem_quota, Capability image,
                   Status* out_status) {
  const Capability table = compartment::table_writable(comp);
  if (!capability_is_valid(table)) {
    return fail_with(out_status, Status::InvalidCapability);
  }

  // The kernel's own entries, checked as everything the kernel hands out is.
  Capability* slot = reinterpret_cast<Capability*>(table);
  slot[compartment::SLOT_LOADER_INVOKE] =
      syscall::gate(syscall::Id::compartment_invoke);
  slot[compartment::SLOT_LOADER_VM_ALLOCATE] =
      syscall::gate(syscall::Id::vm_allocate);
  slot[compartment::SLOT_LOADER_SENTRY] = syscall::gate(syscall::Id::sentry);
  slot[compartment::SLOT_LOADER_FAULT_INSTALL] =
      syscall::gate(syscall::Id::fault_install);
  for (size_t i = compartment::SLOT_LOADER_INVOKE;
       i <= compartment::SLOT_LOADER_FAULT_INSTALL; ++i) {
    inspect::assert_user_capability(slot[i], "loader::prepare");
  }

  // The image is not checked here: only the loader can tell whether it is
  // one, when it reads it. It is passed on read-only (a sealed or local one
  // arrives untagged, and the loader finds nothing to load).
  slot[compartment::SLOT_LOADER_IMAGE] = capability_and_perms(image, perms::Load);
  slot[compartment::SLOT_LOADER_QUOTA] = mem_quota;

  // An entry point that runs the one shared copy of the loader with `comp`'s
  // table: the code stays where it is, only the table is `comp`'s. The code
  // is not in `comp`'s own memory, which `sentry::create` would refuse, so
  // this uses `create_kernel`: the kernel chose the code, and nothing can
  // write it.
  return sentry::create_kernel(comp, s_code, perms::CodeRx, out_status);
}

}  // namespace signetos::loader
