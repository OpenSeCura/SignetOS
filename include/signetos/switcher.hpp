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
// switcher.hpp - The domain switcher: crossing from one compartment to another
//
// `sys_compartment_invoke` (switch.S) is the one way code crosses a
// compartment boundary, kernel or not. It pushes a `ReturnFrame` on the
// thread's kernel stack, has `__signetos_switcher_prepare` check the callee
// and carve its stack out of the caller's by the stack rule (`narrow_stack`),
// enters the callee, and on return has `__signetos_switcher_return` pop the
// frame. The assembly zeroes the callee's stack on the way in and out
// (switch.S, STACK ZEROING). The trap path applies the same stack rule to the
// handlers it delivers (trap.cpp). Entry records -- what a callee is -- are
// sentry.hpp's.
//

#include <stddef.h>
#include <stdint.h>

#include <signetos/sentry.hpp>
#include <signetos/types.hpp>

namespace signetos::switcher {

// Saved caller context pushed onto a thread's kernel stack across a
// synchronous `sys_compartment_invoke` call. Layout matches `asm_macros.h`.
struct alignas(16) ReturnFrame {
  Capability ra;         //   0: caller return address (cra)
  Capability sp;         //  16: caller stack pointer (csp, full bounds)
  Capability gp;         //  32: caller capability table (cgp)
  Capability prev_ksp;   //  48: FRAME LINK -- kernel SP above this frame
                         //      (asm_macros.h)
  Capability s[12];      //  64..240: caller callee-saved registers (cs0..cs11)
  Capability tp;         // 256: caller thread pointer (ctp)
  Capability args[5];    // 272..336: caller's ca1..ca5, the callee's ca0..ca4.
                         //      args[0] is reused for what the caller gets
                         //      back in ca0: the callee's checked return value,
                         //      or the Status of a refused call.
  Capability callee_sp;  // 352: narrowed stack capability for callee
  Capability callee_gp;  // 368: capability table for callee
  uint64_t mstatus;      // 384: caller's `mstatus` at entry (MIE restored on
                         //      return and propagated to a compartment callee)
  uint64_t flags;        // 392: EntryRecord::flags of the callee
  Capability callee_comp;  // 400: the callee's compartment handle (its entry
                           //      record's `owner`; null for a kernel entry):
                           //      whose code runs above this frame
                           //      (trap.hpp, WHO FAULTED)
};

static_assert(sizeof(ReturnFrame) == 26 * sizeof(Capability),
              "ReturnFrame must be 26 capability slots (416 bytes)");

// Helpers called by the assembly domain switcher (`sys_compartment_invoke`):
//   - `__signetos_switcher_prepare` validates `handle` and the caller's `csp`,
//     narrows the stack for the callee (everything below `csp` for a
//     compartment, exactly `min_stack` bytes for a kernel entry), populates
//     `frame->callee_sp`, `frame->callee_gp` and `frame->flags`, advances the
//     hart's `mscratchc` kernel SP to `frame`, and returns the callee's
//     `CT = 1` hardware sentry. On refusal it returns null and leaves the
//     `Status` (as an integer) in `frame->args[0]` for the caller.
//   - `__signetos_switcher_return` is `unwind::resume(KIND_RETURN_FRAME, ret)`
//     (unwind.hpp): pops the top `ReturnFrame` and, if the caller is still
//     there, stores the callee's checked return value in `frame->args[0]` and
//     returns UNWIND_RETURN_FRAME. If the caller's compartment has been
//     destroyed and swept it keeps popping; what it returns is the kind of
//     the frame it stopped at (UNWIND_TRAP_FRAME if that is an interrupted
//     context), or UNWIND_NONE if the return sentry was replayed on an
//     empty/mismatched stack or nothing beneath is live.
extern "C" Capability __signetos_switcher_prepare(Sentry entry_point,
                                                  ReturnFrame* frame);
extern "C" uint64_t __signetos_switcher_return(Capability ret);

// The stack rule. Validates `caller_sp` as a stack anyone may be run on --
// tagged, unsealed, carrying every load/store permission a stack needs
// (including StoreLocal, which only thread stacks have) and no Execute,
// 16-byte aligned with `min_stack` bytes below its address -- and returns
// the slice a callee gets: `[addr - want, addr)` if `want` is non-zero,
// else everything below, `[base, addr)`. The result is exactly
// representable (never rounded up into the caller's frames) and positioned
// at its own top. Null, with the reason in `*out_status`, otherwise.
//
// The switcher applies it to every callee's stack; the trap path applies it
// to the stack an interrupt or fault handler gets (`trap.cpp`).
Capability narrow_stack(Capability caller_sp, uint64_t min_stack,
                        uint64_t want, Status* out_status);

}  // namespace signetos::switcher
