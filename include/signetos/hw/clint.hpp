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
// clint.hpp - Machine timer, cross-hart poke & timebase helpers
//
// Everything runs in M-mode, so the kernel drives the core-local interruptor
// itself, over MMIO, with no firmware in between. The window comes from the
// DTB (`platform::clint_base`, `platform::clint_size`); the registers in it
// sit at the offsets every RISC-V CLINT uses:
//
//   +0x0000 + 4 * hart   `msip`      Bit 0 is the hart's machine software
//                                    interrupt (MSIP, read-only in `mip`):
//                                    1 pokes the hart, 0 clears the poke.
//   +0x4000 + 8 * hart   `mtimecmp`  The hart's machine timer interrupt
//                                    (MTIP) is pending while `mtime` >=
//                                    `mtimecmp`, so one write arms the next
//                                    tick and clears the current one.
//   +0xBFF8              `mtime`     Read through the `time` CSR instead.
//
// `init` derives the kernel's one capability over the window. Every call
// below acts on the calling hart (its `mhartid`) unless it names a hart.
//

#include <stddef.h>
#include <stdint.h>
#include <signetos/hw/platform.hpp>
#include <signetos/types.hpp>

namespace signetos::clint {

// Register offsets within the CLINT window (above).
constexpr uint64_t MSIP_OFFSET     = 0x0000ULL;  // + 4 * hart, 32 bits
constexpr uint64_t MTIMECMP_OFFSET = 0x4000ULL;  // + 8 * hart, 64 bits

// Passing this deadline to `set_timer` clears the pending timer interrupt
// and arms nothing (the compare value can never be reached).
constexpr uint64_t TIMER_OFF = ~0ULL;

// Derives the kernel's capability over the CLINT window from
// `root_data_cap`. Called once by `kernel_main` right after
// `platform::discover`, while addressing is still physical; the window is in
// the identity-mapped device gigabyte (vm.cpp), so the capability keeps
// working once the MMU is on.
void init(Capability root_data_cap);

// Current `time` (Zicntr): the CLINT's `mtime`, readable in M-mode without
// any counter enable.
inline uint64_t now() {
  uint64_t t;
  __asm__ volatile("csrr %0, time" : "=r"(t));
  return t;
}

// Converts microseconds to `time` CSR ticks using the `/cpus`
// `timebase-frequency` discovered from the DTB (platform.hpp).
inline uint64_t us_to_ticks(uint64_t us) {
  return us * (platform::timebase_hz() / 1'000'000);
}

// And back, rounding down.
inline uint64_t ticks_to_us(uint64_t ticks) {
  return ticks / (platform::timebase_hz() / 1'000'000);
}

// Arms the machine timer interrupt on the calling hart for absolute
// `time == deadline` and clears any pending one.
void set_timer(uint64_t deadline);

// Raises the machine software interrupt (MSIP) on every DTB-present hart
// whose bit is set in `hart_mask`.
void send_ipi(uint64_t hart_mask);

// Clears the calling hart's machine software interrupt. MSIP is read-only in
// `mip`; writing the hart's `msip` is the only way to clear it.
void clear_ipi();

// A capability to `hart`'s `msip` alone (4 bytes, Load|Store), for code that
// clears its hart's pokes without calling in here: a parked secondary hart
// (`HartBootSlot`, thread.cpp). Null if `hart` is not present.
Capability msip_register(uint64_t hart);

}  // namespace signetos::clint
