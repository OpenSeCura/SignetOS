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
// smp.hpp - Bringing up the secondary harts, and stopping them
//
// The boot hart starts every other hart present in the DTB: it carves each
// one's stacks, fills in its slot in `_hart_boot_table` (linker.ld) and pokes
// it with an IPI. The parked hart (`.Lsecondary_wait_loop` in boot.S) picks up
// its slot, turns the MMU on and calls `secondary_hart_init`, which runs the
// per-hart initialisation (`thread::init_hart`, `irq::init_hart`). It then
// parks: it sleeps, and all it does is answer pokes (`on_poke`).
//
// THE STOP
// --------
// Some things one hart can only do with every other hart standing still, and
// each has to follow at once: a revocation sweep's step to a new generation
// is the one there is (vm.hpp, CHECKED PAGES; the generation is a bit of
// each hart's own `mstatus`, and the kernel's mappings carry it for all of
// them). `stop_others` pokes every other hart and waits until each has
// stopped; `release_others` lets them go, and each takes the caller's
// generation and drops its cached translations before it runs anything else.
//
// WHERE A HART STOPS. In the poke itself (`on_poke`), and a hart takes a
// poke only where the kernel on it is in the middle of nothing: interrupted
// in a compartment's code, or parked. The kernel runs masked, so a hart
// inside a system call finishes the call first; the caller of `stop_others`
// waits for it, and therefore holds no lock while it waits. What a stopped
// hart was running is all in memory by then: the trap saved every register
// of the interrupted thread on that thread's kernel stack, in its state
// pages (thread.hpp), which is where the caller finds them
// (`thread::state_on`), and where the hart takes them back from when it
// goes on.
//
// A stopped hart sleeps, and so does the caller while it waits: each change
// of state is followed by a poke to whoever waits for it.
//
// ONE AT A TIME. Two harts that asked at once would each wait for the other
// to stop. Whoever calls `stop_others` sees to it that nobody else does
// (revoke.cpp: one hart starts a sweep).
//

#include <stddef.h>
#include <stdint.h>
#include <signetos/types.hpp>

namespace signetos::smp {

// Brings up every secondary hart present in the DTB (`platform::hart_present`),
// carving each hart's 64 KiB host stack (`csp`) and 16 KiB kernel entry stack
// (`mscratchc`) from the identity-mapped kernel region above `_kernel_end` and
// waiting until each hart has completed `thread::init_hart` and
// `irq::init_hart`. Called on the boot hart, after it has done both itself.
void bring_up_secondary_harts(Capability root_data_cap, uint64_t boot_hart);

// Number of harts that have completed their per-hart initialisation, the boot
// hart included.
size_t online_harts();

// The same harts, one bit each.
uint64_t online_mask();

// THE STOP. Stops every other online hart, and returns once each has
// stopped. Called masked, with no lock held, by one hart at a time; followed
// by `release_others`.
void stop_others();

// Lets the harts `stop_others` stopped go, and returns once each has taken
// this hart's generation and dropped its translations.
void release_others();

// This hart took the kernel's poke (irq.hpp): clears it, and stops here if
// another hart has asked (THE STOP). From the trap dispatcher, and from a
// parked hart, which takes its pokes without a trap.
void on_poke();

}  // namespace signetos::smp
