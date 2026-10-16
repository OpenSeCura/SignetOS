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
 * irq.cpp - The two interrupt handlers, and every hart's interrupt state
 * (irq.hpp)
 */

#include <signetos/hw/clint.hpp>
#include <signetos/irq.hpp>
#include <signetos/lock.hpp>
#include <signetos/sentry.hpp>
#include <signetos/thread.hpp>

namespace signetos::irq {
namespace {

SpinLock s_lock;
// The two interrupt handlers (irq.hpp, INTERRUPT HANDLERS): each written
// once, by `install`, under `s_lock`, and only read after that. A capability
// is stored and loaded in one access, so a reader on another hart sees null
// or the handler, never half of one.
Capability s_timer_handler = nullptr;
Capability s_external_handler = nullptr;

// `mie` bits. `MSTATUS_MPIE` comes from asm_macros.h.
constexpr uint64_t MIE_MSIE = 1ULL << 3;
constexpr uint64_t MIE_MTIE = 1ULL << 7;
constexpr uint64_t MIE_MEIE = 1ULL << 11;

uint64_t tick_ticks() { return clint::us_to_ticks(TICK_US); }

// The harts that have run `init_hart`, one bit per hart number: the harts a
// poke is sent to.
uint64_t s_harts_up = 0;

void arm_tick() {
  __asm__ volatile("csrs mie, %0" : : "r"(MIE_MTIE));
  clint::set_timer(clint::now() + tick_ticks());
}

// Clears MTIE as well, so on each hart MTIE is set exactly while that hart's
// tick is armed (`sync_this_hart` reads it that way).
void disarm_tick() {
  clint::set_timer(clint::TIMER_OFF);
  __asm__ volatile("csrc mie, %0" : : "r"(MIE_MTIE));
}


// Brings this hart's `mie` and timer in line with the installed handlers:
// the poke bit always set, MEIE set once the external handler is installed,
// and the tick armed once the timer handler is. Handlers are never removed,
// so this only ever turns things on.
void sync_this_hart() {
  uint64_t on = MIE_MSIE;
  if (handler_for(IRQ_M_EXT) != nullptr) {
    on |= MIE_MEIE;
  }
  __asm__ volatile("csrs mie, %0" : : "r"(on));

  uint64_t mie = 0;
  __asm__ volatile("csrr %0, mie" : "=r"(mie));
  if (handler_for(IRQ_M_TIMER) != nullptr && (mie & MIE_MTIE) == 0) {
    arm_tick();
  }
}

// Pokes every other hart that is up. The fence makes an install before it
// visible to a poked hart before that hart reads the handlers; the poked
// hart fences too (`__signetos_trap_dispatch`).
void poke_other_harts() {
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
  const uint64_t others = __atomic_load_n(&s_harts_up, __ATOMIC_SEQ_CST) &
                          ~(1ULL << thread::this_hart());
  if (others != 0) {
    clint::send_ipi(others);
  }
}

// This hart now, every other hart when the poke this sends arrives.
void sync_all_harts() {
  sync_this_hart();
  poke_other_harts();
}

}  // namespace

Capability handler_for(uint64_t irq) {
  const Capability* field = irq == IRQ_M_TIMER ? &s_timer_handler
                            : irq == IRQ_M_EXT ? &s_external_handler
                                               : nullptr;
  if (field == nullptr) {
    return nullptr;
  }
  __atomic_thread_fence(__ATOMIC_ACQUIRE);
  return *static_cast<const volatile Capability*>(field);
}

void init() {
  s_lock = SpinLock{};
  s_timer_handler = nullptr;
  s_external_handler = nullptr;
}

void init_hart() {
  // A known start, so that MTIE means "this hart's tick is armed" from here
  // on: only the poke bit on, the timer off, and no poke pending (the one
  // that started a secondary hart is still set, thread.cpp).
  clint::set_timer(clint::TIMER_OFF);
  clint::clear_ipi();
  __asm__ volatile("csrw mie, %0" : : "r"(MIE_MSIE));

  // Publish this hart, then read the handlers. An install does the opposite
  // -- writes a handler, then reads `s_harts_up` (`poke_other_harts`). Both
  // sides write, fence, then read, so at least one sees the other: either
  // the installer pokes this hart, or the sync below sees the handler.
  __atomic_fetch_or(&s_harts_up, 1ULL << thread::this_hart(),
                    __ATOMIC_SEQ_CST);
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
  sync_this_hart();
}

Status install(uint64_t irq, Capability handler) {
  // Only the tick and the external interrupt have handlers (irq.hpp,
  // INTERRUPT HANDLERS); the software interrupt is the kernel's.
  Capability* field = irq == IRQ_M_TIMER ? &s_timer_handler
                      : irq == IRQ_M_EXT ? &s_external_handler
                                         : nullptr;
  if (field == nullptr) {
    return Status::InvalidAuthority;
  }
  // The kernel keeps the handle, and nothing it remembers may be local.
  if ((capability_get_perms(handler) & perms::Global) == 0) {
    return Status::InvalidSentry;
  }
  // A compartment's entry: the dispatcher runs it with the entry's own
  // compartment and table. A kernel entry is refused: a system call is not
  // an interrupt handler.
  sentry::Entry entry{};
  if (sentry::resolve(handler, &entry) != Status::Ok ||
      (entry.flags & sentry::ENTRY_FLAG_TRUSTED) != 0) {
    return Status::InvalidSentry;
  }

  {
    Locked hold(s_lock);
    if (*field != nullptr) {
      return Status::Busy;
    }
    *static_cast<volatile Capability*>(field) = handler;
  }
  sync_all_harts();
  return Status::Ok;
}

void on_poke() {
  // Cleared before the handlers are read, so a poke sent after that sets it
  // again and brings this hart back here.
  clint::clear_ipi();
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
  sync_this_hart();
}

void rearm_tick() { clint::set_timer(clint::now() + tick_ticks()); }

void silence(uint64_t irq) {
  if (irq == IRQ_M_TIMER) {
    disarm_tick();  // MTIP can only be cleared by reprogramming the timer
  } else {
    __asm__ volatile("csrc mie, %0"
                     :
                     : "r"(1ULL << (irq & ~trap::INTERRUPT_BIT)));
  }
}

}  // namespace signetos::irq
