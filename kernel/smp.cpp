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
 * smp.cpp - Bringing up the secondary harts, and stopping them (smp.hpp)
 */

#include <signetos/asm_macros.h>
#include <signetos/hw/clint.hpp>
#include <signetos/hw/platform.hpp>
#include <signetos/irq.hpp>
#include <signetos/smp.hpp>
#include <signetos/thread.hpp>
#include <signetos/debug/report.hpp>
#include <signetos/vm.hpp>

// sweep.S: this hart stops, and goes on when the hart that asked says so.
extern "C" void __signetos_stop_here(void* stop,
                                     signetos::Capability own_msip,
                                     signetos::Capability starter_msip);

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
};
static_assert(sizeof(HartBootSlot) == 64);

size_t s_online_harts = 0;
uint64_t s_online_mask = 0;

// THE STOP (smp.hpp). Integers only, and the first four where sweep.S
// expects them: a stopped hart reads them while it may load no capability.
constexpr uint64_t PHASE_NONE = 0;
constexpr uint64_t PHASE_STOP = STOP_PHASE_STOP;  // stop, and wait
constexpr uint64_t PHASE_GO = 2;                  // follow, and go on
struct Stop {
  uint64_t phase;
  uint64_t stopped;  // harts that have stopped
  uint64_t resumed;  // harts that have gone on
  uint64_t ucrg;     // the `mstatus.UCRG` they go on with
  uint64_t starter;  // the hart that asked
  uint64_t mask;     // the harts it asked
  uint64_t count;    // how many those are
};
static_assert(__builtin_offsetof(Stop, phase) == STOP_PHASE &&
              __builtin_offsetof(Stop, stopped) == STOP_STOPPED &&
              __builtin_offsetof(Stop, resumed) == STOP_RESUMED &&
              __builtin_offsetof(Stop, ucrg) == STOP_UCRG);
Stop s_stop;

// Sleeps until `*count` is `n`. Every hart that changes it pokes this one
// afterwards, and this one clears its poke before it looks, so a change made
// after the look ends the `wfi`. Only a poke does: a tick that falls due
// meanwhile stays pending, and `mie` is put back for it.
void wait_for(const uint64_t* count, uint64_t n) {
  uint64_t mie = 0;
  __asm__ volatile("csrr %0, mie" : "=r"(mie));
  __asm__ volatile("csrw mie, %0" : : "r"(static_cast<uint64_t>(MIE_MSIE)));
  for (;;) {
    clint::clear_ipi();
    if (__atomic_load_n(count, __ATOMIC_ACQUIRE) == n) {
      break;
    }
    __asm__ volatile("wfi");
  }
  __asm__ volatile("csrw mie, %0" : : "r"(mie));
}

}  // namespace

void bring_up_secondary_harts(Capability root_data_cap, uint64_t boot_hart) {
  // The boot hart has done its own per-hart initialisation already.
  __atomic_fetch_add(&s_online_harts, 1, __ATOMIC_SEQ_CST);
  __atomic_fetch_or(&s_online_mask, 1ULL << boot_hart, __ATOMIC_SEQ_CST);

  if (!capability_is_valid(root_data_cap)) {
    return;
  }
  // A hart comes up in generation 0 (boot.S), which is every hart's until
  // the first sweep: no hart is brought up after that.
  if (vm::generation() != 0) {
    debug::panic("smp: a hart brought up after a sweep has started");
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

uint64_t online_mask() {
  return __atomic_load_n(&s_online_mask, __ATOMIC_ACQUIRE);
}

void stop_others() {
  const uint64_t me = thread::this_hart();
  if (__atomic_load_n(&s_stop.phase, __ATOMIC_ACQUIRE) != PHASE_NONE) {
    debug::panic("smp: two harts stopping the others at once");
  }
  s_stop.starter = me;
  s_stop.mask = online_mask() & ~(1ULL << me);
  s_stop.count = 0;
  for (uint64_t h = 0; h < platform::MAX_HARTS; ++h) {
    s_stop.count += (s_stop.mask >> h) & 1;
  }
  if (s_stop.count == 0) {
    return;
  }
  __atomic_store_n(&s_stop.stopped, 0ULL, __ATOMIC_RELAXED);
  __atomic_store_n(&s_stop.resumed, 0ULL, __ATOMIC_RELAXED);
  __atomic_store_n(&s_stop.phase, PHASE_STOP, __ATOMIC_RELEASE);
  clint::send_ipi(s_stop.mask);
  wait_for(&s_stop.stopped, s_stop.count);
}

void release_others() {
  if (s_stop.count == 0) {
    return;
  }
  uint64_t mstatus = 0;
  __asm__ volatile("csrr %0, mstatus" : "=r"(mstatus));
  s_stop.ucrg = mstatus & MSTATUS_UCRG;
  __atomic_store_n(&s_stop.phase, PHASE_GO, __ATOMIC_RELEASE);
  clint::send_ipi(s_stop.mask);
  wait_for(&s_stop.resumed, s_stop.count);
  __atomic_store_n(&s_stop.phase, PHASE_NONE, __ATOMIC_RELEASE);
}

void on_poke() {
  clint::clear_ipi();
  if (__atomic_load_n(&s_stop.phase, __ATOMIC_ACQUIRE) != PHASE_STOP) {
    return;
  }
  // Asked: every hart the stop names, which is never the one that asked.
  const uint64_t me = thread::this_hart();
  if ((s_stop.mask & (1ULL << me)) == 0) {
    return;
  }
  __signetos_stop_here(&s_stop, clint::msip_register(me),
                       clint::msip_register(s_stop.starter));
}

}  // namespace signetos::smp

// A parked hart's whole life (boot.S, `.Lsecondary_idle`): called each time
// a poke ends its `wfi`. In an SMP_SELFTEST=1 build one of them is handed a
// thread to run instead (kernel/debug/smp_selftest.cpp).
extern "C" void __signetos_parked_poke() {
  signetos::smp::on_poke();
#ifdef SIGNETOS_SMP_SELFTEST
  signetos::debug::smp_self_test_poke();
#endif
}

// Called by `.Lsecondary_start` in boot.S on each secondary hart, with the
// MMU on and its own stacks installed.
extern "C" void secondary_hart_init(uint64_t hartid) {
  signetos::thread::init_hart(hartid);
  signetos::irq::init_hart();
  __atomic_fetch_add(&signetos::smp::s_online_harts, 1, __ATOMIC_SEQ_CST);
  __atomic_fetch_or(&signetos::smp::s_online_mask, 1ULL << hartid,
                    __ATOMIC_SEQ_CST);
}
