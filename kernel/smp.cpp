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
 * smp.cpp - Bringing up the secondary harts (smp.hpp)
 */

#include <signetos/hw/clint.hpp>
#include <signetos/hw/platform.hpp>
#include <signetos/irq.hpp>
#include <signetos/smp.hpp>
#include <signetos/thread.hpp>
#include <signetos/debug/report.hpp>
#include <signetos/vm.hpp>

namespace signetos::smp {
namespace {

// Per-hart boot handoff slot in `_hart_boot_table` (linker.ld, 64 bytes/hart).
// Offsets are matched by `.Lsecondary_wait_loop` / `.Lsecondary_start` in
// `kernel/boot.S`.
struct alignas(64) HartBootSlot {
  Capability sp;      // +0:  64 KiB host stack (cursor at top)
  Capability ksp;     // +16: 16 KiB kernel entry stack (cursor at top)
  uint64_t satp;      // +32: Sv39 satp value
  uint64_t state;     // +40: 0 = waiting, 1 = go, 2 = online
  Capability msip;    // +48: this hart's CLINT `msip`, which the parked hart
                      //      writes to clear each poke (clint.hpp)
};
static_assert(sizeof(HartBootSlot) == 64);

size_t s_online_harts = 0;

}  // namespace

void bring_up_secondary_harts(Capability root_data_cap, uint64_t boot_hart) {
  // The boot hart has done its own per-hart initialisation already.
  __atomic_fetch_add(&s_online_harts, 1, __ATOMIC_SEQ_CST);

  if (!capability_is_valid(root_data_cap)) {
    return;
  }

  uint64_t table_pa = 0;
  uint64_t kend_pa = 0;
  {
    Capability c;
    __asm__ volatile("llc %0, _hart_boot_table" : "=C"(c));
    table_pa = capability_get_address(c);
    __asm__ volatile("llc %0, _kernel_end" : "=C"(c));
    kend_pa = capability_get_address(c);
  }

  Capability table_cap = capability_set_address(root_data_cap, table_pa);
  table_cap = capability_set_bounds(table_cap,
                                    platform::MAX_HARTS * sizeof(HartBootSlot));
  table_cap = capability_and_perms(table_cap, perms::DataRw);
  auto* table = reinterpret_cast<HartBootSlot*>(table_cap);

  uint64_t satp_val = 0;
  __asm__ volatile("csrr %0, satp" : "=r"(satp_val));

  constexpr uint64_t HOST_STACK_BYTES = 65536ULL;
  constexpr uint64_t KSP_STACK_BYTES  = 16384ULL;
  uint64_t cursor =
      (kend_pa + (HOST_STACK_BYTES - 1)) & ~(HOST_STACK_BYTES - 1);
  const uint64_t limit = vm::kernel_base() + vm::KERNEL_SIZE;

  for (uint64_t h = 0; h < platform::MAX_HARTS; ++h) {
    if (h == boot_hart || !platform::hart_present(h)) {
      continue;
    }
    if (cursor + HOST_STACK_BYTES + KSP_STACK_BYTES > limit) {
      debug::panic("smp: out of boot region for secondary hart stacks");
    }

    Capability sp = capability_set_address(root_data_cap, cursor);
    sp = capability_set_bounds(sp, HOST_STACK_BYTES);
    sp = capability_and_perms(sp, perms::DataRw);
    sp = capability_set_address(sp, cursor + HOST_STACK_BYTES);

    const uint64_t ksp_base = cursor + HOST_STACK_BYTES;
    Capability ksp = capability_set_address(root_data_cap, ksp_base);
    ksp = capability_set_bounds(ksp, KSP_STACK_BYTES);
    ksp = capability_and_perms(ksp, perms::DataRw);
    ksp = capability_set_address(ksp, ksp_base + KSP_STACK_BYTES);

    cursor = (ksp_base + KSP_STACK_BYTES + (HOST_STACK_BYTES - 1)) &
             ~(HOST_STACK_BYTES - 1);

    table[h].sp = sp;
    table[h].ksp = ksp;
    table[h].satp = satp_val;
    table[h].msip = clint::msip_register(h);
    __atomic_store_n(&table[h].state, 1ULL, __ATOMIC_RELEASE);

    clint::send_ipi(1ULL << h);

    while (__atomic_load_n(&table[h].state, __ATOMIC_ACQUIRE) != 2ULL) {
    }
  }

  debug::harts_online(online_harts(), platform::hart_count(), boot_hart);
}

size_t online_harts() {
  return __atomic_load_n(&s_online_harts, __ATOMIC_ACQUIRE);
}

}  // namespace signetos::smp

// Called by `.Lsecondary_start` in boot.S on each secondary hart, with the
// MMU on and its own stacks installed.
extern "C" void secondary_hart_init(uint64_t hartid) {
  signetos::thread::init_hart(hartid);
  signetos::irq::init_hart();
  __atomic_fetch_add(&signetos::smp::s_online_harts, 1, __ATOMIC_SEQ_CST);
}
