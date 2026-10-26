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
 * irq.cpp - The interrupt handler, and every hart's interrupt state
 * (irq.hpp)
 */

#include <signetos/hw/clint.hpp>
#include <signetos/irq.hpp>
#include <signetos/thread.hpp>

namespace signetos::irq {
namespace {

// `mie` bits. `MSTATUS_MPIE` comes from asm_macros.h.
constexpr uint64_t MIE_MSIE = 1ULL << 3;
constexpr uint64_t MIE_MTIE = 1ULL << 7;
constexpr uint64_t MIE_MEIE = 1ULL << 11;

uint64_t tick_ticks() { return clint::us_to_ticks(TICK_US); }

}  // namespace

void init_hart() {
  // A known start: only the poke bit on, the timer off, and no poke pending
  // (the one that started a secondary hart is still set, thread.cpp).
  clint::set_timer(clint::TIMER_OFF);
  clint::clear_ipi();
  __asm__ volatile("csrw mie, %0" : : "r"(MIE_MSIE));
}

Status install(Capability thread) {
  const Status s = thread::install_handler(thread);
  if (s != Status::Ok) {
    return s;
  }
  __asm__ volatile("csrs mie, %0" : : "r"(MIE_MEIE | MIE_MTIE));
  rearm_tick();
  return Status::Ok;
}

void on_poke() { clint::clear_ipi(); }

void rearm_tick() { clint::set_timer(clint::now() + tick_ticks()); }

void silence(uint64_t irq) {
  if (irq == IRQ_M_TIMER) {
    // MTIP can only be cleared by reprogramming the timer.
    clint::set_timer(clint::TIMER_OFF);
    __asm__ volatile("csrc mie, %0" : : "r"(MIE_MTIE));
  } else {
    __asm__ volatile("csrc mie, %0"
                     :
                     : "r"(1ULL << (irq & ~trap::INTERRUPT_BIT)));
  }
}

}  // namespace signetos::irq
