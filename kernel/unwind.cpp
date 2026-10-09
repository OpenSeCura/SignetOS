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

//
// unwind.cpp - Returning through frames whose compartment no longer exists
// (unwind.hpp).
//

#include <stddef.h>

#include <signetos/asm_macros.h>
#include <signetos/inspect.hpp>
#include <signetos/sentry.hpp>
#include <signetos/thread.hpp>
#include <signetos/trap.hpp>
#include <signetos/uart.hpp>
#include <signetos/unwind.hpp>

namespace signetos::unwind {

static_assert(KIND_NONE == UNWIND_NONE &&
                  KIND_RETURN_FRAME == UNWIND_RETURN_FRAME &&
                  KIND_TRAP_FRAME == UNWIND_TRAP_FRAME,
              "unwind::Kind must match the UNWIND_* codes the assembly tests");
static_assert(offsetof(sentry::ReturnFrame, prev_ksp) == FRAME_LINK &&
                  offsetof(trap::TrapFrame, active_kernel_sp) == FRAME_LINK &&
                  offsetof(thread::SwitchFrame, active_kernel_sp) == FRAME_LINK,
              "every kernel frame keeps its link at FRAME_LINK");
static_assert(offsetof(sentry::ReturnFrame, tp) == RET_FRAME_TP &&
                  offsetof(trap::TrapFrame, tp) == FRAME_TP &&
                  offsetof(thread::SwitchFrame, tp) == FRAME_TP,
              "ctp save slots must match asm_macros.h");
static_assert(sizeof(sentry::ReturnFrame) == RET_FRAME_SIZE &&
                  sizeof(trap::TrapFrame) == TRAP_FRAME_SIZE &&
                  sizeof(thread::SwitchFrame) == SWITCH_FRAME_SIZE,
              "frame sizes must match asm_macros.h");
static_assert(RET_FRAME_SIZE != TRAP_FRAME_SIZE &&
                  RET_FRAME_SIZE != SWITCH_FRAME_SIZE &&
                  TRAP_FRAME_SIZE != SWITCH_FRAME_SIZE,
              "kind_at tells frames apart by their size");

namespace {

void wipe(Capability* slot, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    slot[i] = nullptr;
  }
}

// Scrubs the whole of `region`'s bounds: the stack slice loaned to a callee
// (`ReturnFrame::callee_sp`) or a handler (`TrapFrame::handler_sp`), so
// nothing it left behind, data or capability, reaches whoever resumes. For a
// compartment callee that is everything below the caller's `csp`; for a
// kernel entry it is the `min_stack` slice.
void scrub(Capability region) {
  if (!capability_is_valid(region)) {
    return;
  }
  const uint64_t base = capability_get_base(region);
  wipe(reinterpret_cast<Capability*>(capability_set_address(region, base)),
       capability_get_length(region) / sizeof(Capability));
}

// The kernel SP kept in the frame at `ksp` (FRAME LINK): where the frame
// beneath it starts.
Capability link_of(Capability ksp) {
  return *reinterpret_cast<const Capability*>(
      capability_set_address(ksp, capability_get_address(ksp) + FRAME_LINK));
}

// What happens to the code about to be resumed (unwind.hpp, KILLED THREADS).
enum class Fate {
  Run,  // resume it as usual
  End,  // end the thread instead
  Cut,  // skip it: its caller gets Status::Killed
};

// `below` is the frame under the one being popped: it says whose code is
// about to be resumed.
Fate fate_of(Capability below) {
  if (!thread::current_kill_pending()) {
    return Fate::Run;
  }
  const Kind kind = kind_at(below);
  if (kind == KIND_NONE) {
    return Fate::End;  // nothing beneath: the thread's own code
  }
  // `below` is the call (`ReturnFrame`) or trap delivery (`TrapFrame`) into
  // that code. Both carry its flags.
  const uint64_t flags =
      kind == KIND_RETURN_FRAME
          ? reinterpret_cast<const sentry::ReturnFrame*>(below)->flags
          : reinterpret_cast<const trap::TrapFrame*>(below)->flags;
  if ((flags & sentry::ENTRY_FLAG_TRUSTED_TO_FINISH) != 0) {
    return Fate::Run;  // the kernel, or a compartment trusted to finish
  }
  return Fate::Cut;
}

}  // namespace

Kind kind_at(Capability ksp) {
  if (!capability_is_valid(ksp)) {
    return KIND_NONE;
  }
  const uint64_t base = capability_get_base(ksp);
  const uint64_t top = base + capability_get_length(ksp);
  const uint64_t addr = capability_get_address(ksp);
  if (addr < base || addr + FRAME_LINK + sizeof(Capability) > top) {
    return KIND_NONE;
  }
  // FRAME LINK (asm_macros.h): every frame keeps, at the same offset, the
  // kernel SP from just above it -- the kernel stack's own bounds, which no
  // compartment can hold, written by whoever pushed the frame. Its address
  // says how big the frame is, and so what kind it is.
  const Capability link = *reinterpret_cast<const Capability*>(
      capability_set_address(ksp, addr + FRAME_LINK));
  if (!capability_is_valid(link) || capability_get_base(link) != base ||
      capability_get_length(link) != top - base ||
      capability_get_address(link) > top) {
    return KIND_NONE;
  }
  switch (capability_get_address(link) - addr) {
    case sizeof(sentry::ReturnFrame):
      return KIND_RETURN_FRAME;
    case sizeof(trap::TrapFrame):
      return KIND_TRAP_FRAME;
    default:
      // A `SwitchFrame` (512) is never on top when a return path runs: it is
      // popped by `__thread_restore` before user code runs again. Not
      // something to resume.
      return KIND_NONE;
  }
}

Kind resume(Kind expected_top, Capability value) {
  bool popped = false;
  for (;;) {
    const Capability ksp = thread::current_kernel_sp();
    const Kind kind = kind_at(ksp);
    // The first frame must be the kind the return path expects, so a stashed
    // return sentry used out of turn (a switcher return over a `TrapFrame`,
    // a trap return over a `ReturnFrame`, either on an empty stack) is
    // refused before anything is popped.
    if (kind == KIND_NONE || (!popped && kind != expected_top)) {
      if (popped) {
        uart::print("[unwind] ending thread ");
        uart::print_dec(thread::current_tid());
        uart::print(": every frame on its kernel stack is in a destroyed "
                    "compartment\n");
      }
      return KIND_NONE;
    }
    popped = true;

    const Fate fate = fate_of(link_of(ksp));
    if (fate == Fate::End) {
      uart::print("[unwind] ending thread ");
      uart::print_dec(thread::current_tid());
      uart::print(": killed\n");
      thread::exit(-1);
      uart::panic("unwind: a killed thread did not end");
    }

    if (kind == KIND_RETURN_FRAME) {
      auto* f = reinterpret_cast<sentry::ReturnFrame*>(ksp);
      thread::set_kernel_sp(f->prev_ksp);  // pop
      scrub(f->callee_sp);
      // The caller is live if its return address still has its tag. Only
      // `ra` is judged: a host-context caller has no `cgp`, and a
      // compartment's code and table die together anyway. The saved caller
      // registers are reloaded as-is by the assembly: the caller already held
      // every one of them, and CHERI monotonicity means they cannot have
      // widened.
      if (fate == Fate::Run && capability_is_valid(f->ra)) {
        inspect::assert_user_capability(value, "unwind:ca0");
        f->args[0] = value;
        return KIND_RETURN_FRAME;
      }
      wipe(reinterpret_cast<Capability*>(f),
           sizeof(sentry::ReturnFrame) / sizeof(Capability));
    } else {
      auto* f = reinterpret_cast<trap::TrapFrame*>(ksp);
      thread::set_kernel_sp(f->active_kernel_sp);  // pop
      scrub(f->handler_sp);
      // The interrupted code is live if `sepcc` still has its tag; it is
      // resumed as if its handler had returned. `sret` sets SIE := SPIE, and
      // the SPIE the hardware holds now is stale if anything trapped or
      // switched threads since the trap was taken, so set it from the
      // `sstatus` recorded then: the interrupted code resumes with exactly
      // the SIE it had.
      if (fate == Fate::Run && capability_is_valid(f->sepcc)) {
        if ((f->sstatus & SSTATUS_SPIE) != 0) {
          __asm__ volatile("csrs sstatus, %0" : : "r"(SSTATUS_SPIE));
        } else {
          __asm__ volatile("csrc sstatus, %0" : : "r"(SSTATUS_SPIE));
        }
        return KIND_TRAP_FRAME;
      }
      wipe(reinterpret_cast<Capability*>(f),
           sizeof(trap::TrapFrame) / sizeof(Capability));
    }

    // The frame just skipped was cut for a kill, or belonged to a compartment
    // that is gone. Whoever is beneath it is told which instead of getting a
    // return value.
    value = reinterpret_cast<Capability>(static_cast<uintptr_t>(
        fate == Fate::Cut ? Status::Killed : Status::CompartmentDestroyed));
  }
}

}  // namespace signetos::unwind
