/*
 * Copyright 2026 Google LLC (Cherified Team)
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
// platform.hpp - What the kernel needs to know about the board
//
// `discover()` walks the DTB passed by OpenSBI at boot (while physical
// addressing is still on, through `fdt.hpp`) and records only the facts the
// kernel itself depends on:
//
//   - Physical RAM (`/memory*`: `reg`)             frame allocator, direct map
//   - Usable harts (`/cpus/cpu@*`: `reg`, `status`) per-hart state, IPIs
//   - Timer frequency (`/cpus`: `timebase-frequency`)  the kernel tick
//   - Console UART (`"ns16550a"`, preferring `/chosen` `stdout-path`: `reg`)
//                                                  boot banner, panic
//   - Finisher / poweroff device (`"sifive,test*"`: `reg`)  `qemu_poweroff`
//   - Where the DTB itself is, so `init::launch` can hand `init` a copy
//
// Everything else about the board -- the PLIC, its per-hart contexts, the
// UART's interrupt, virtio transports -- is policy about devices the kernel
// never touches. `init` reads those out of the DTB copy it is given
// (`user/init.cpp`) and hands the right windows to the right drivers.
//
// Fallback values match QEMU's default `virt` board if no valid DTB is given.
//

#include <stddef.h>
#include <stdint.h>
#include <signetos/types.hpp>

namespace signetos::platform {

// Ceiling on hart IDs tracked in fixed-size arrays (`thread::s_cpus`,
// `TrapMgrInterface::plic_s_context`). Harts present in the DTB are recorded
// up to this limit; `thread::init_hart` refuses any hart ID that was not
// enabled in the DTB or lies at or above `MAX_HARTS`.
constexpr size_t MAX_HARTS = 16;

// Ceiling on VirtIO MMIO transport slots user space tracks (`BlkInterface`).
constexpr size_t MAX_VIRTIO_SLOTS = 8;

// Sentinel for "this hart has no S-mode PLIC context".
constexpr uint32_t PLIC_NO_CONTEXT = ~0u;

// Standard RISC-V / SiFive PLIC architectural register offsets within the
// PLIC MMIO window (fixed by the PLIC specification, not board-specific).
// Used by `user/trap_mgr.cpp`; the kernel never touches the PLIC.
constexpr uint64_t PLIC_PRIORITY       = 0x000000ULL;  // + 4 * source
constexpr uint64_t PLIC_PENDING        = 0x001000ULL;  // + 4 * (source / 32)
constexpr uint64_t PLIC_ENABLE_STRIDE  = 0x80ULL;      // per context
constexpr uint64_t PLIC_ENABLE_BASE    = 0x002000ULL;  // + ctx * stride + 4 * (source / 32)
constexpr uint64_t PLIC_CONTEXT_STRIDE = 0x1000ULL;    // per context
constexpr uint64_t PLIC_CONTEXT_BASE   = 0x200000ULL;  // + ctx * stride: threshold
constexpr uint64_t PLIC_CLAIM_OFFSET   = 0x4ULL;       // threshold + 4: claim/complete
constexpr uint32_t PLIC_MAX_SOURCE     = 1023;         // source 0 is reserved

// Minimum PLIC MMIO window length (in bytes) needed to reach context `ctx`'s
// priority, enable and threshold/claim registers.
constexpr uint64_t plic_window_for_context(uint64_t ctx) {
  return PLIC_CONTEXT_BASE + ((ctx + 1) * PLIC_CONTEXT_STRIDE);
}

// Fallback defaults matching QEMU `virt` when no DTB is provided.
constexpr uint64_t DEFAULT_RAM_BASE         = 0x80000000ULL;
constexpr uint64_t DEFAULT_RAM_BYTES        = 2ULL * 1024 * 1024 * 1024;
constexpr uint64_t DEFAULT_TIMEBASE_HZ      = 10'000'000ULL;
constexpr uint64_t DEFAULT_CLINT_BASE       = 0x02000000ULL;
constexpr uint64_t DEFAULT_TEST_DEVICE_BASE = 0x00100000ULL;
constexpr uint64_t DEFAULT_TEST_DEVICE_SIZE = 0x1000ULL;
constexpr uint64_t DEFAULT_UART_BASE        = 0x10000000ULL;
constexpr uint64_t DEFAULT_UART_SIZE        = 0x1000ULL;
constexpr size_t   DEFAULT_HARTS            = 4;
constexpr uint32_t DEFAULT_PLIC_NDEV        = 96;  // user-space fallback

// Walks the Flattened Device Tree at `dtb_cap` (using `root_data_cap` while
// physical addressing is still active) and populates the board properties
// below. Safe to call multiple times; idempotent once discovered.
void discover(Capability root_data_cap, Capability dtb_cap);
bool is_discovered();

// Physical RAM (`/memory`).
uint64_t ram_base();
uint64_t ram_bytes();

// Harts (`/cpus/cpu@*`), timer frequency (`/cpus` `timebase-frequency`), and
// CLINT base (`"riscv,clint0"` / `"sifive,clint0"`).
size_t   hart_count();
bool     hart_present(uint64_t hart);
uint64_t timebase_hz();
uint64_t clint_base();

// Finisher / poweroff device (`"sifive,test1"` / `"sifive,test0"`).
uint64_t test_device_base();
uint64_t test_device_size();

// Console UART (`"ns16550a"`), page-rounded.
uint64_t uart_base();
uint64_t uart_size();

// The DTB blob itself: physical address and `totalsize`, both 0 if no valid
// DTB was found. `frame::init` keeps these frames out of the pool so the
// blob survives until `init::launch` copies it for `init`.
uint64_t dtb_base();
uint64_t dtb_bytes();

}  // namespace signetos::platform
