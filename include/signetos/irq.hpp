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
// irq.hpp - The interrupt handler, and every hart's interrupt state
//
// Who the interrupts go to, and keeping each hart's `mie` and timer in line
// with that. Waking the handler is the trap dispatcher's and thread.cpp's
// (thread.hpp, THE INTERRUPT HANDLER); this only says who it is.
//
// THE INTERRUPT HANDLER
// ---------------------
// Both interrupts that ever leave the kernel go to the scheduler:
// IRQ_M_TIMER, the kernel tick, and IRQ_M_EXT, the one wire every PLIC
// device shares. The scheduler owns the PLIC and wakes the driver thread
// waiting for each device source (sched.cpp, DEVICE INTERRUPTS). It is also
// told when a thread has to wait for a page (PAGE_WAIT, vm.hpp). On each
// hart the handler is an ordinary thread, created on the scheduler's
// interrupt entry, that waits in `sys_trap_wait` and is woken with an
// `Event` (below). The software interrupt is the kernel's own (below), and
// nothing else can fire on this machine.
//
// `init` installs the handler at boot, with `sys_trap_install(thread)`, once
// it has brought up the scheduler: for the hart it runs on, which is the
// only hart that runs threads. A hart's handler is installed once and never
// removed or replaced; if it ends, that hart's interrupts are silenced. The
// authority is the system call's gate: `init` is seeded with every gate and
// hands this one to nobody. `sys_trap_wait` needs no authority of its own:
// only the thread installed on this hart can wait in it.
//
// THE KERNEL TICK
// ---------------
// The kernel owns the machine timer, which it drives itself through the
// CLINT (clint.hpp). Installing a hart's handler arms a fixed periodic tick
// (`TICK_US`) on that hart; before every wake for it the kernel re-arms the
// next tick, so the handler only ever observes the interrupt (no syscall
// exists to program the timer). A tick with no handler waiting for it
// disarms that hart's timer.
//
// THE EXTERNAL INTERRUPT
// ----------------------
// `IRQ_M_EXT` is gated by its `mie` bit: set when a hart's handler is
// installed, and cleared on the spot on a hart where it arrives with no
// handler waiting. The kernel does nothing device-specific: the PLIC is a
// device window delegated to the scheduler, and claiming and completing the
// source there -- which is what drops the level-triggered interrupt -- is
// the scheduler's job. The handler runs masked, so a source that is not
// claimed simply fires again once it waits.
//
// SEVERAL HARTS
// -------------
// `mie` and the timer belong to a hart, and a hart can only change its own.
// A handler is installed for the hart that installs it, and that hart turns
// its own interrupts on, so no hart has to tell another. Which hart a device
// interrupt is sent to is not decided here: that is a PLIC setting, and the
// scheduler owns the PLIC.
//
// THE SOFTWARE INTERRUPT IS THE KERNEL'S
// --------------------------------------
// The poke is the machine software interrupt (`IRQ_M_SOFT`), sent by setting
// the target hart's CLINT `msip` (`clint::send_ipi`). It is the only way one
// hart can interrupt another, and it carries no message, so it cannot be
// shared: if a compartment could handle it, the kernel could not tell its
// own pokes from the compartment's. It never goes to the handler, its `mie`
// bit is always set, and the trap dispatcher hands it to `on_poke`. Today
// only boot sends one, to start a secondary hart.
//

#include <stdint.h>

#include <signetos/trap.hpp>
#include <signetos/types.hpp>

namespace signetos::irq {

using trap::IRQ_M_EXT;
using trap::IRQ_M_SOFT;
using trap::IRQ_M_TIMER;
using trap::PAGE_WAIT;

// Period of the kernel tick.
constexpr uint64_t TICK_US = 10'000;

// What the handler is woken with, written to the `Event` it passed to
// `sys_trap_wait`: the cause (IRQ_M_TIMER, IRQ_M_EXT or PAGE_WAIT), the id of
// the thread it interrupted, and for PAGE_WAIT the pager's id (0: none).
struct Event {
  uint64_t cause;
  uint64_t tid;
  uint64_t aux;
};

// Per-hart initialisation: turns on this hart's poke bit, turns its timer
// off and clears any poke left pending. Every hart calls it once, on itself,
// after `thread::init_hart`.
void init_hart();

// Core of `sys_trap_install` (THE INTERRUPT HANDLER, above): makes `thread`
// this hart's handler (`thread::install_handler`) and turns on this hart's
// tick and external interrupt.
Status install(Capability thread);

// This hart took the kernel's poke (THE SOFTWARE INTERRUPT IS THE KERNEL'S):
// clears it.
void on_poke();

// Sets this hart's next tick, `TICK_US` from now. Clears a pending timer
// interrupt, which only reprogramming the timer can do.
void rearm_tick();

// Silences `irq` on this hart, which took it with no handler waiting: the
// timer is disarmed, any other interrupt has its `mie` bit cleared.
void silence(uint64_t irq);

}  // namespace signetos::irq
