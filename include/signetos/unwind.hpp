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
// `resume` is also where a killed thread (thread.hpp, `kill`) is stopped:
// it runs every time the kernel hands control back to compartment code. The
// frame under the one being popped says whose code that is, and so what
// happens to it:
//
//   - nothing beneath: the thread's own code (the compartment it was created
//     in, inside no call). The thread ends there instead of running on.
//   - the kernel, or a compartment marked trusted to finish
//     (compartment.hpp, `trust_to_finish`): it runs on and returns as usual.
//     This holds for trap handlers too.
//   - any other compartment: it is cut. Its frame is skipped and wiped, its
//     caller gets Status::Killed instead of a return value, and the same
//     rule is applied to that caller.
//
// The rule is applied only when the thread is resumed: at every return from
// a call, and at the end of every trap, the timer tick included, so a thread
// that is running meets it within a tick. One that is asleep would not, which
// is why the scheduler wakes a killed thread and never sleeps it again
// (`sched.thread_kill`). So a killed thread ends after at most a tick of its
// own CPU time, unless it is inside code trusted to finish.
//

#include <signetos/types.hpp>

namespace signetos::unwind {

using Status = signetos::Status;

// Which kind of frame sits at a kernel stack pointer. Mirrored in
// asm_macros.h as UNWIND_*: it is what the two return paths get back in a0.
enum Kind : uint64_t {
  KIND_NONE = 0,          // nothing recognisable: empty stack, or not a frame
  KIND_RETURN_FRAME = 1,  // sentry::ReturnFrame, resumed with `ret`
  KIND_TRAP_FRAME = 2,    // trap::TrapFrame, resumed with `sret`
};

// Identifies the frame at `ksp` by its FRAME LINK (asm_macros.h): the
// capability at offset 48 of every kernel frame, tagged, with the kernel
// stack's own bounds and the address just above the frame. Only the kernel
// writes such a value, at push. The distance from the frame to that address
// is the frame's size, and so its kind. Checks the stack's bounds before
// reading anything.
Kind kind_at(Capability ksp);

// Pops frames from the current hart's kernel stack (`sscratchc`) until one
// can be resumed, and returns its kind; KIND_NONE if the top frame is not an
// `expected_top` (a replayed return sentry -- the caller ends the thread) or
// if every frame was dead. On return `sscratchc` sits just above the frame
// to resume: the assembly finds it at `sscratchc - RET_FRAME_SIZE` or
// `sscratchc - TRAP_FRAME_SIZE`.
//
// `value` is what the first `ReturnFrame` resumed gets in `args[0]` if no
// frame was skipped (the callee's return value); after a skipped frame it is
// Status::CompartmentDestroyed, or Status::Killed if the frame was cut for a
// kill. A `TrapFrame` resumed has its `sstatus.SPIE`
// restored from the frame. Each popped frame's loaned stack slice
// (`callee_sp` / `handler_sp`) is scrubbed whether it is resumed or skipped;
// a skipped frame is wiped.
Kind resume(Kind expected_top, Capability value);

}  // namespace signetos::unwind
