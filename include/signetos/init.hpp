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

#pragma once

//
// init.hpp - SignetOS Initial User-Space Compartment (`init`) Bootstrap
//
// PACKAGING & BOOTSTRAP OVERVIEW
// ------------------------------
// Each boot user-space compartment (`boot/<name>.cpp`) is compiled and linked as
// a standalone binary (`boot/<name>.bin`) with `user/compartment.ld`
// and `user/entry.S`, then embedded into `.rodata.boot_images` via
// `kernel/boot_images.S`.
//
// At boot, `init::launch(system_quota, thread_quota)`:
//   1. Creates the `init` compartment funded by `system_quota` and populates
//      its capability table ONLY with architectural kernel authorities:
//        - All kernel syscall gates (`syscall::gate(Id)`)
//        - `root_quota_thread_mem`
//   2. Loads `boot/init.bin` into `init`'s own memory, processes its
//      `__cap_relocs`, and mints `init`'s entry-point sentry.
//   3. Passes a read-only capability to a `BootManifest` struct as `init`'s
//      `initial_arg` (`ca0`), containing the UART MMIO capability and read-only
//      capabilities to the embedded core service images.
//   4. Dispatches the initial `init` thread (`sys_thread_switch`), which
//      provisions quotas and capability tables for each core compartment.
//
// The capability-table layouts of the user-space services that `init`
// provisions are user-space ABI and live in `user/abi.hpp`; the kernel
// does not depend on them.
//

#include <stddef.h>
#include <stdint.h>
#include <signetos/compartment.hpp>
#include <signetos/hw/platform.hpp>
#include <signetos/syscall.hpp>
#include <signetos/trap.hpp>
#include <signetos/types.hpp>

namespace signetos::init {

// Default stack size for the initial `init` thread (16 KiB = 4 pages).
constexpr size_t INIT_STACK_SIZE = 16 * 1024;

// Header at offset 0 of every standalone compartment binary (`user/entry.S`).
constexpr uint64_t COMPARTMENT_IMAGE_MAGIC = 0x5349474e434f4d50ULL;  // "SIGNCOMP"

struct CompartmentImageHeader {
  uint32_t jump_insn;         //  0: `j _compartment_trampoline`
  uint32_t nops[3];           //  4..15: padding to 16-byte boundary
  uint64_t magic;             // 16: COMPARTMENT_IMAGE_MAGIC
  uint64_t cap_relocs_start;  // 24: offset of `__cap_relocs` start
  uint64_t cap_relocs_end;    // 32: offset of `__cap_relocs` end
  uint64_t rodata_end;        // 40: end of `.text` + `.rodata`
  uint64_t bss_end;           // 48: total in-memory size including `.bss`
  uint64_t got_end;           // 56: end of `.got`; the executable prefix
  uint64_t manifest_start;    // 64: the `.manifest` block (user/manifest.hpp):
  uint64_t manifest_end;      // 72: what the image asks its launcher for; equal
                              //     offsets when it carries none
  uint64_t fault_handler;     // 80: `compartment_error_handler`, or 0
  uint64_t reserved_;         // 88: 0
};

static_assert(sizeof(CompartmentImageHeader) == 96,
              "CompartmentImageHeader must be 96 bytes (6 capabilities)");

// Validates `img_cap` as a compartment image and returns its header, or
// nullptr if the capability is not a readable image with the right magic.
// The cursor has to be the base: `image_install` copies
// `capability_get_length()` bytes from the cursor, which is only inside the
// bounds when nothing was rounded away below it (an image that is not
// exactly representable has a base below its symbol; see
// `kernel/boot_images.S`).
inline const CompartmentImageHeader* image_header(Capability img_cap) {
  if (!capability_is_valid(img_cap) ||
      capability_get_address(img_cap) != capability_get_base(img_cap) ||
      capability_get_length(img_cap) < sizeof(CompartmentImageHeader)) {
    return nullptr;
  }
  const auto* hdr = reinterpret_cast<const CompartmentImageHeader*>(img_cap);
  return (hdr->magic == COMPARTMENT_IMAGE_MAGIC) ? hdr : nullptr;
}

// The part of an installed image (`code_mem`) its entry capability may cover:
// `[0, got_end)` -- `.text`, `.rodata`, `__cap_relocs` and `.got`. The `.got`
// has to be inside because purecap code reaches it PC-relative; `.data` and
// `.bss` stay out, so nothing a compartment can write is something it can
// execute (its `.text` is reachable only through the read-only `.got`
// entries `image_install` makes). Returns nullptr if the header's `got_end`
// is not a sane, exactly representable prefix of `code_mem`.
inline Capability image_code_window(Capability code_mem,
                                    const CompartmentImageHeader* hdr) {
  const uint64_t got_end = hdr->got_end;
  if (got_end == 0 || (got_end & (sizeof(Capability) - 1)) != 0 ||
      got_end < hdr->cap_relocs_end || got_end < hdr->rodata_end ||
      got_end > capability_get_length(code_mem)) {
    return nullptr;
  }
  Capability code =
      capability_set_address(code_mem, capability_get_base(code_mem));
  code = capability_set_bounds(code, got_end);
  if (!capability_is_valid(code) || capability_get_length(code) != got_end) {
    return nullptr;  // would round up into `.data`
  }
  return code;
}

// The code capability for the image's fault handler (`hdr->fault_handler`):
// `code` (from `image_code_window`) with its cursor moved to `offset`.
// Returns true with `*out = nullptr` when `offset` is 0 (no handler),
// true with the capability when `offset` is a 4-byte-aligned address past the
// header and inside `code`, and false (a malformed image) otherwise.
inline bool image_fault_handler(Capability code, uint64_t offset,
                                Capability* out) {
  *out = nullptr;
  if (offset == 0) {
    return true;
  }
  if ((offset & 3) != 0 || offset < sizeof(CompartmentImageHeader) ||
      offset >= capability_get_length(code)) {
    return false;
  }
  *out = capability_set_address(code, capability_get_base(code) + offset);
  return capability_is_valid(*out);
}

// Bytes to allocate for an image: the file bytes plus any trailing `.bss`.
inline size_t image_alloc_size(const CompartmentImageHeader* hdr,
                               Capability img_cap) {
  const size_t img_len = capability_get_length(img_cap);
  return (hdr->bss_end > img_len) ? static_cast<size_t>(hdr->bss_end) : img_len;
}

// Copies the image bytes into `code_mem` (a zeroed allocation of at least
// `image_alloc_size`) and resolves its internal `__cap_relocs` records (each
// 5 x uint64_t = 40 bytes) into `.got`, so that `.rodata` string literals and
// `.data`/`.bss` objects are reachable through tagged, tightly-bounded
// capabilities before the entry capability is narrowed to `CodeRx`.
// Shared by the kernel (`init::launch`) and the user runtime loader.
inline void image_install(Capability code_mem, Capability img_cap,
                          const CompartmentImageHeader* hdr) {
  const size_t img_len = capability_get_length(img_cap);
  const auto* src = reinterpret_cast<const uint8_t*>(img_cap);
  auto* dst = reinterpret_cast<uint8_t*>(code_mem);
  for (size_t i = 0; i < img_len; ++i) {
    dst[i] = src[i];
  }

  const uint64_t alloc_base = capability_get_base(code_mem);
  const uint64_t alloc_len = capability_get_length(code_mem);
  uint64_t reloc_off = hdr->cap_relocs_start;
  while (reloc_off + 40 <= hdr->cap_relocs_end && reloc_off + 40 <= img_len) {
    const auto* rec = reinterpret_cast<const uint64_t*>(src + reloc_off);
    const uint64_t cap_loc = rec[0];
    const uint64_t obj_base = rec[1];
    const uint64_t addend = rec[2];
    const uint64_t obj_size = rec[3];

    if (cap_loc + sizeof(Capability) <= alloc_len &&
        (cap_loc & (sizeof(Capability) - 1)) == 0) {
      auto* slot = reinterpret_cast<Capability*>(
          capability_set_address(code_mem, alloc_base + cap_loc));
      if (obj_base == 0 && obj_size == 0) {
        *slot = nullptr;
      } else if (obj_base <= alloc_len) {
        Capability target =
            capability_set_address(code_mem, alloc_base + obj_base);
        if (obj_size > 0 && obj_base + obj_size <= alloc_len) {
          target = capability_set_bounds(target, obj_size);
        }
        target = capability_set_address(target, alloc_base + obj_base + addend);
        if (obj_base < hdr->rodata_end) {
          target = capability_and_perms(target, perms::ReadOnly);
        }
        *slot = target;
      }
    }
    reloc_off += 40;
  }
}

// Read-only bootstrap manifest passed to `init` in `ca0` (`initial_arg`).
// Carries the raw facts user space needs to bring the machine up: a copy of
// the device tree, one capability over the whole device MMIO range, and
// read-only capabilities to the packaged compartment images so they do not
// occupy hardcoded slots in `init`'s capability table.
//
// The kernel does no device policy: which devices exist, where their
// registers are, which PLIC source and context they use, how large a DMA
// arena to carve - `init` works all of that out from `dtb` (fdt.hpp) and
// narrows `mmio` down to one window per driver (`boot/init.cpp`).
//
// Only the boot set is packaged: what `init` needs to reach the disk. Every
// other service (`naming`, `sched`, `trap_mgr`, `shell`) is a file on the
// disk, read through `fs` and loaded by `init`.
struct alignas(16) BootManifest {
  Capability dtb;           // read-only copy of the flattened device tree
  Capability mmio;          // read/write window over [0, GIGAPAGE_SIZE): the
                            // whole device range the kernel maps
  Capability uart_img;      // `boot/uart.bin`
  Capability dma_img;       // `boot/dma.bin`
  Capability blk_img;       // `boot/blk.bin`
  Capability fs_img;        // `boot/fs.bin`
};

// `init` compartment capability table layout: the seeds the kernel installs,
// starting at `RW_SLOT_SEED_BASE`. `compartment::create` gives seeds no
// meaning; this layout is the kernel's choice as `init`'s creator, the way a
// manifest is an image's (user/manifest.hpp).
constexpr size_t RW_SLOT_VM_QUOTA =
    compartment::RW_SLOT_SEED_BASE;                  // root QuotaVm (funds init)
constexpr size_t RW_SLOT_SYSCALL_BASE = RW_SLOT_VM_QUOTA + 1;
constexpr size_t RW_SLOT_THREAD_QUOTA =
    RW_SLOT_SYSCALL_BASE + syscall::kSyscallCount;   // root_quota_thread_mem
constexpr size_t RW_SLOT_SEAL_SCHED =
    RW_SLOT_THREAD_QUOTA + 1;                        // OType::QuotaSched authority
constexpr size_t RW_SLOT_SEAL_DISK =
    RW_SLOT_SEAL_SCHED + 1;                          // OType::QuotaDisk authority
constexpr size_t RW_SLOT_SEAL_TYPE_KEY =
    RW_SLOT_SEAL_DISK + 1;                           // OType::TypeKey authority
constexpr size_t RW_SLOT_SEAL_OBJECT =
    RW_SLOT_SEAL_TYPE_KEY + 1;                       // OType::SealedObject authority

constexpr size_t INIT_SEED_COUNT =
    (RW_SLOT_SEAL_OBJECT + 1) - compartment::RW_SLOT_SEED_BASE;

// Written by `init` (not seeded): the scheduler's dispatcher entry point.
// After the `init` thread exits, `launch()` reads this slot back; if it holds
// an `OType::EntryPoint`, the kernel creates a thread on it from
// `thread_quota` and re-dispatches that thread every time the running thread
// exits. That thread is the user-level scheduler's run loop; the kernel never
// picks threads itself.
constexpr size_t RW_SLOT_SCHED_RUN = RW_SLOT_SEAL_OBJECT + 1;
constexpr size_t SCHED_RUN_STACK_SIZE = 16 * 1024;

using Status = signetos::Status;
using signetos::status_name;

// Launches the `init` compartment funded by `system_quota` and its initial
// thread funded by `thread_quota`, and dispatches `init` to provision all core
// compartments. Once the `init` thread has exited, drives the scheduler's
// dispatcher thread (`RW_SLOT_SCHED_RUN`) until it exits, if `init` published
// one; otherwise returns immediately. If `out_init_comp` is non-null it
// receives the `init` compartment handle.
Status launch(Capability system_quota, Capability thread_quota,
              Capability* out_init_comp = nullptr);

}  // namespace signetos::init
