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
// irq.hpp - The two interrupt handlers, and every hart's interrupt state
//
// Which handler each interrupt goes to, and keeping each hart's `mie` and
// timer in line with that. Delivering an interrupt to its handler is the
// trap dispatcher's (trap.hpp); this only says who it goes to.
//
// INTERRUPT HANDLERS
// ------------------
// Only two interrupts ever leave the kernel, each to one fixed handler:
//   - IRQ_M_TIMER, the kernel tick, to the scheduler;
//   - IRQ_M_EXT, the one wire every PLIC device shares, to the trap manager,
//     which owns the PLIC and routes each device source to its driver.
// The software interrupt is the kernel's own (below), and nothing else can
// fire on this machine.
//
// `init` installs both handlers at boot, with `sys_trap_install(irq,
// entry)`, once it has brought up the compartment that owns each. Each can
// be installed once and is never removed or replaced. The authority is the
// system call's gate: `init` is seeded with every gate and hands this one to
// nobody.
//
//
// THE KERNEL TICK
// ---------------
// The kernel owns the machine timer, which it drives itself through the
// CLINT (clint.hpp). Installing the `IRQ_M_TIMER` handler arms a fixed
// periodic tick (`TICK_US`) on every hart; before every delivery to the
// handler the kernel re-arms that hart's next tick, so the handler only ever
// observes the interrupt (no syscall exists to program the timer). A tick
// whose handler no longer resolves (its compartment was destroyed) disarms
// that hart's timer.
//
// THE EXTERNAL INTERRUPT
// ----------------------
// `IRQ_M_EXT` is gated by its `mie` bit: set once its handler is installed,
// and cleared on the spot on a hart where it arrives with no handler that
// resolves. The kernel does nothing device-specific: the PLIC is a device
// window delegated to the trap manager, and claiming and completing the
// source there -- which is what drops the level-triggered interrupt -- is
// that handler's job. The handler runs masked, so a source that is not
// claimed simply fires again at the next `mret`.
//
// SEVERAL HARTS
// -------------
// `mie` and the timer belong to a hart, and a hart can only change its own.
// So each hart keeps its own `mie` and timer in line with the installed
// handlers (`sync_all_harts`): an install brings its own hart in line and
// then pokes every other hart, which brings itself in line when the poke
// arrives. Which hart a device interrupt is sent to is not
// decided here: that is a PLIC setting, and `trap_mgr` owns the PLIC.
//
// THE SOFTWARE INTERRUPT IS THE KERNEL'S
// --------------------------------------
// The poke is the machine software interrupt (`IRQ_M_SOFT`), sent by setting
// the target hart's CLINT `msip` (`clint::send_ipi`). It is the only way one
// hart can interrupt another, and it carries no message, so it cannot be
// shared: if a compartment could handle it, the kernel could not tell its
// own pokes from the compartment's. `install` refuses it, its `mie` bit is
// always set, and the trap dispatcher hands it to `on_poke`.
//

#include <stdint.h>

#include <signetos/trap.hpp>
#include <signetos/types.hpp>

namespace signetos::irq {

using trap::IRQ_M_EXT;
using trap::IRQ_M_SOFT;
using trap::IRQ_M_TIMER;
using trap::PAGE_WAIT;

// Period of the kernel tick delivered to the `IRQ_M_TIMER` handler.
constexpr uint64_t TICK_US = 10'000;

// No handlers installed.
void init();

// Per-hart initialisation: turns on this hart's poke bit, turns its timer
// off, clears any poke left pending, adds the hart to the ones that pokes are
// sent to, and brings its `mie` and timer in line with the installed
// handlers. Every hart calls it once, on itself, after `thread::init_hart`
// (and the boot hart after `init`).
void init_hart();

// Core of `sys_trap_install` (INTERRUPT HANDLERS, above): makes `handler`,
// a compartment `OType::EntryPoint`, the handler of `irq` -- IRQ_M_TIMER or
// IRQ_M_EXT; anything else is InvalidAuthority -- and brings every hart in
// line. Busy if `irq` already has one: each is installed once, for good.
// InvalidSentry if `handler` does not resolve to a compartment entry, or is
// local (the kernel keeps it).
Status install(uint64_t irq, Capability handler);

// The handler installed for `irq`, or null. It may no longer resolve: its
// compartment may have been destroyed.
Capability handler_for(uint64_t irq);

// This hart took the kernel's poke (THE SOFTWARE INTERRUPT IS THE KERNEL'S):
// clears it, then brings this hart's `mie` and timer in line.
void on_poke();

// Sets this hart's next tick, `TICK_US` from now. Clears a pending timer
// interrupt, which only reprogramming the timer can do.
void rearm_tick();

// Silences `irq` on this hart, which took it with no handler that resolves:
// the timer is disarmed, any other interrupt has its `mie` bit cleared.
void silence(uint64_t irq);

}  // namespace signetos::irq
