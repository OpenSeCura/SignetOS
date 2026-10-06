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
// sbi.hpp - Supervisor timer, cross-hart IPI & timebase helpers (-bios none)
//
// `boot.S` sets each hart's `mscratchc` to its 64-byte `MScratch` entry in
// `_m_scratch` and installs `_m_trap_entry` in `mtvecc` before dropping to
// S-mode. After `platform::discover` reads the CLINT MMIO base and present
// harts from the DTB, `sbi::init` populates each present hart's `MScratch`
// with bounded `msip_cap` (4 bytes) and `mtimecmp_cap` (8 bytes) capabilities:
//   - `set_timer(deadline)` (`a7 = 0`) traps to `_m_trap_entry` to program
//     this hart's `mtimecmp` and clear `mip.STIP`.
//   - `send_ipi(hart_mask)` (`a7 = 1`) traps to `_m_trap_entry` to raise
//     `mip.SSIP` on each target hart (directly for self, or via CLINT `msip`
//     for remote harts).
//

#include <stdint.h>
#include <signetos/platform.hpp>

namespace signetos::sbi {

// Per-hart M-mode trap scratch slot in `_m_scratch` (linker.ld, 64 bytes/hart).
// Offsets are matched by `_m_trap_entry` in `kernel/boot.S`.
struct alignas(64) MScratch {
  Capability saved_ct1;     // +0:  caller ct1 saved across _m_trap_entry
  Capability msip_cap;      // +16: 4-byte DataRw cap at clint_base + 4 * hart
  Capability mtimecmp_cap;  // +32: 8-byte DataRw cap at clint_base + 0x4000 + 8 * hart
  Capability pad;           // +48
};
static_assert(sizeof(MScratch) == 64);

// Standard RISC-V CLINT register offsets within the CLINT MMIO window
// (architectural offsets; base address comes from the DTB via `platform::clint_base()`).
constexpr uint64_t CLINT_MSIP_OFFSET     = 0x0000ULL;
constexpr uint64_t CLINT_MTIMECMP_OFFSET = 0x4000ULL;

// Passing this deadline to `set_timer` clears the pending timer interrupt
// and arms nothing (the compare value can never be reached).
constexpr uint64_t TIMER_OFF = ~0ULL;

// Populates `_m_scratch[0..MAX_HARTS-1]` with bounded capabilities to each
// DTB-present hart's CLINT `msip` and `mtimecmp` registers. Called once by
// `kernel_main` right after `platform::discover`.
inline void init(Capability root_data_cap) {
  if (!capability_is_valid(root_data_cap)) {
    return;
  }
  Capability sym;
  __asm__ volatile("llc %0, _m_scratch" : "=C"(sym));
  const uint64_t scratch_pa = capability_get_address(sym);

  Capability table_cap = capability_set_address(root_data_cap, scratch_pa);
  table_cap =
      capability_set_bounds(table_cap, platform::MAX_HARTS * sizeof(MScratch));
  table_cap = capability_and_perms(table_cap, perms::DataRw);
  auto* table = reinterpret_cast<MScratch*>(table_cap);

  const uint64_t clint = platform::clint_base();
  for (size_t h = 0; h < platform::MAX_HARTS; ++h) {
    table[h].saved_ct1 = nullptr;
    table[h].pad = nullptr;
    if (platform::hart_present(h)) {
      Capability msip =
          capability_set_address(root_data_cap, clint + CLINT_MSIP_OFFSET + 4 * h);
      msip = capability_set_bounds(msip, sizeof(uint32_t));
      msip = capability_and_perms(msip, perms::DataRw);
      table[h].msip_cap = msip;

      Capability mtimecmp = capability_set_address(
          root_data_cap, clint + CLINT_MTIMECMP_OFFSET + 8 * h);
      mtimecmp = capability_set_bounds(mtimecmp, sizeof(uint64_t));
      mtimecmp = capability_and_perms(mtimecmp, perms::DataRw);
      table[h].mtimecmp_cap = mtimecmp;
    } else {
      table[h].msip_cap = nullptr;
      table[h].mtimecmp_cap = nullptr;
    }
  }
}

// Current `time` (Zicntr; readable from S-mode because `boot.S` sets
// `mcounteren.TM`).
inline uint64_t now() {
  uint64_t t;
  __asm__ volatile("csrr %0, time" : "=r"(t));
  return t;
}

// Arms the supervisor timer interrupt on the calling hart for absolute
// `time == deadline` and clears any pending one via `_m_trap_entry`.
inline void set_timer(uint64_t deadline) {
  register uint64_t a0 __asm__("a0") = deadline;
  register uint64_t a7 __asm__("a7") = 0;
  __asm__ volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");
}

// Raises the supervisor software interrupt (`sip.SSIP`) on every DTB-present
// hart whose bit is set in `hart_mask`.
inline long send_ipi(uint64_t hart_mask) {
  for (uint64_t h = 0; h < platform::MAX_HARTS; ++h) {
    if ((hart_mask & (1ULL << h)) == 0 || !platform::hart_present(h)) {
      continue;
    }
    register uint64_t a0 __asm__("a0") = h;
    register uint64_t a7 __asm__("a7") = 1;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");
  }
  return 0;
}

// Converts microseconds to `time` CSR ticks using the `/cpus`
// `timebase-frequency` discovered from the DTB (platform.hpp).
inline uint64_t us_to_ticks(uint64_t us) {
  return us * (platform::timebase_hz() / 1'000'000);
}

}  // namespace signetos::sbi
