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
// unwind.hpp - Returning through frames whose compartment no longer exists
//
// A compartment can be destroyed while threads are inside it (compartment.hpp,
// DESTROY WHILE THREADS ARE INSIDE). Its memory is quarantined, not unmapped,
// so those threads keep running its code until the revocation sweep clears
// every capability into it -- including the return addresses the switcher and
// the trap dispatcher saved on their kernel stacks. From then on a return into
// that compartment has nowhere to go. This is what resolves it: the frame
// whose return address has lost its tag is popped and skipped, and the nearest
// frame beneath that is still live is the one resumed, with
// Status::CompartmentDestroyed in place of a return value if it is a
// `ReturnFrame`. A `TrapFrame` whose interrupted code is still live is resumed
// as if its handler had returned. If nothing beneath is live, the thread ends.
//
// KILLED THREADS
//
// `resume` is also where a killed thread (thread.hpp, `kill`) ends: when the
// kernel is about to hand control back to the thread's own code -- the
// compartment it was created in, inside no call, which is when nothing lies
// beneath the frame being popped. Nothing else is ever cut short: a call the
// thread has made into another compartment runs to its return, as a kill
// never leaves a compartment half-way through anything. A kill is "return
// this thread to its owner" (DESIGN.md §2.3, §7).
//
// The check is made whenever the thread is resumed: at every return from a
// call, and at the end of every trap, the timer tick included. So a killed
// thread in its own code ends within a tick, whatever that code does. One
// inside a call ends once the call returns: the scheduler sees to it that a
// killed thread never sleeps (`sched.thread_kill`; its `block` returns
// SCHED_KILLED at once), so a callee that waits is sent back with an error,
// and a callee that computes finishes. A callee that neither returns nor
// waits keeps the thread; that is the callee's bug, or its owner's business
// (destroy it, and the thread is unwound past it).
//

#include <signetos/fault.hpp>
#include <signetos/types.hpp>

namespace signetos::unwind {

using Status = signetos::Status;

// Which kind of frame sits at a kernel stack pointer. Mirrored in
// asm_macros.h as UNWIND_*: it is what the two return paths get back in a0.
enum Kind : uint64_t {
  KIND_NONE = 0,          // nothing recognisable: empty stack, or not a frame
  KIND_RETURN_FRAME = 1,  // switcher::ReturnFrame, resumed with `ret`
  KIND_TRAP_FRAME = 2,    // trap::TrapFrame, resumed with `mret`
};

// Identifies the frame at `ksp` by its FRAME LINK (asm_macros.h): the
// capability at offset 48 of every kernel frame, tagged, with the kernel
// stack's own bounds and the address just above the frame. Only the kernel
// writes such a value, at push. The distance from the frame to that address
// is the frame's size, and so its kind. Checks the stack's bounds before
// reading anything.
Kind kind_at(Capability ksp);

// Pops frames from the current hart's kernel stack (`mscratchc`) until one
// can be resumed, and returns its kind; KIND_NONE if the top frame is not an
// `expected_top` (a replayed return sentry -- the caller ends the thread) or
// if every frame was dead. On return `mscratchc` sits just above the frame
// to resume: the assembly finds it at `mscratchc - RET_FRAME_SIZE` or
// `mscratchc - TRAP_FRAME_SIZE`.
//
// `value` is what the first `ReturnFrame` resumed gets in `args[0]` if no
// frame was skipped (the callee's return value); after a skipped frame it is
// Status::CompartmentDestroyed, or the frame's `fault_status`
// (Status::Faulted) if it was a fault frame. A `TrapFrame` resumed has its
// `mstatus.MPIE` restored from the frame. Nothing here zeroes stacks: the
// assembly zeroes the slice the resumed frame lent (`callee_sp` /
// `handler_sp`), which covers every slice above it (switch.S, STACK
// ZEROING).
//
// FAULT FRAMES (trap.hpp, TRAP_FLAG_FAULT; fault.hpp)
//
// A `TrapFrame` pushed for a fault in compartment code is resumed only if it
// is the top frame (the one whose handler has just returned) and `verdict`,
// that handler's return value, is fault::INSTALL_CONTEXT: its registers are
// then reloaded from the ErrorState the handler left, and `mepcc` from the
// faulting PCC re-addressed to the ErrorState's `pc` (trap::install_context).
// Anything else abandons the faulting code: the frame is skipped like a dead
// one.
Kind resume(Kind expected_top, Capability value,
            uint64_t verdict = fault::UNWIND);

}  // namespace signetos::unwind
