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
#include <signetos/debug/inspect.hpp>
#include <signetos/sentry.hpp>
#include <signetos/switcher.hpp>
#include <signetos/thread.hpp>
#include <signetos/trap.hpp>
#include <signetos/debug/report.hpp>
#include <signetos/unwind.hpp>

namespace signetos::unwind {

static_assert(KIND_NONE == UNWIND_NONE &&
                  KIND_RETURN_FRAME == UNWIND_RETURN_FRAME &&
                  KIND_TRAP_FRAME == UNWIND_TRAP_FRAME,
              "unwind::Kind must match the UNWIND_* codes the assembly tests");
static_assert(offsetof(switcher::ReturnFrame, prev_ksp) == FRAME_LINK &&
                  offsetof(trap::TrapFrame, active_kernel_sp) == FRAME_LINK,
              "every kernel frame keeps its link at FRAME_LINK");
static_assert(offsetof(switcher::ReturnFrame, tp) == RET_FRAME_TP &&
                  offsetof(trap::TrapFrame, tp) == FRAME_TP,
              "ctp save slots must match asm_macros.h");
static_assert(sizeof(switcher::ReturnFrame) == RET_FRAME_SIZE &&
                  sizeof(trap::TrapFrame) == TRAP_FRAME_SIZE,
              "frame sizes must match asm_macros.h");
static_assert(RET_FRAME_SIZE != TRAP_FRAME_SIZE,
              "kind_at tells frames apart by their size");

namespace {

// The kernel SP kept in the frame at `ksp` (FRAME LINK): where the frame
// beneath it starts.
Capability link_of(Capability ksp) {
  return *reinterpret_cast<const Capability*>(
      capability_set_address(ksp, capability_get_address(ksp) + FRAME_LINK));
}

// True if the code about to be resumed is a killed thread's own: nothing
// beneath `below`, the frame under the one being popped, so the thread is
// inside no call. That is where, and only where, a killed thread ends
// (unwind.hpp, KILLED THREADS).
bool kill_lands_here(Capability below) {
  return thread::current_kill_pending() && kind_at(below) == KIND_NONE;
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
    case sizeof(switcher::ReturnFrame):
      return KIND_RETURN_FRAME;
    case sizeof(trap::TrapFrame):
      return KIND_TRAP_FRAME;
    default:
      return KIND_NONE;
  }
}

Kind resume(Kind expected_top, Capability value, uint64_t verdict) {
  bool popped = false;
  bool faulted = false;  // a fault frame was skipped on the way
  for (;;) {
    const Capability ksp = thread::current_kernel_sp();
    const Kind kind = kind_at(ksp);
    // The first frame must be the kind the return path expects, so a stashed
    // return sentry used out of turn (a switcher return over a `TrapFrame`,
    // a trap return over a `ReturnFrame`, either on an empty stack) is
    // refused before anything is popped.
    if (kind == KIND_NONE || (!popped && kind != expected_top)) {
      if (popped) {
        debug::thread_ending(
            "unwind", faulted ? "its own code faulted, with nothing beneath "
                                "to unwind to"
                              : "every frame on its kernel stack is in a "
                                "destroyed compartment");
      }
      return KIND_NONE;
    }
    const bool first = !popped;  // the frame whose code just returned
    popped = true;

    if (kill_lands_here(link_of(ksp))) {
      debug::thread_ending("unwind", "killed");
      thread::exit(-1);
      debug::panic("unwind: a killed thread did not end");
    }

    if (kind == KIND_RETURN_FRAME) {
      auto* f = reinterpret_cast<switcher::ReturnFrame*>(ksp);
      thread::set_kernel_sp(f->prev_ksp);  // pop
      // The caller is live if its return address still has its tag. Only
      // `ra` is judged: a host-context caller has no `cgp`, and a
      // compartment's code and table die together anyway. The saved caller
      // registers are reloaded as-is by the assembly: the caller already held
      // every one of them, and CHERI monotonicity means they cannot have
      // widened.
      if (capability_is_valid(f->ra)) {
        inspect::assert_user_capability(value, "unwind:ca0");
        f->args[0] = value;
        return KIND_RETURN_FRAME;
      }
    } else {
      auto* f = reinterpret_cast<trap::TrapFrame*>(ksp);
      thread::set_kernel_sp(f->active_kernel_sp);  // pop
      // The interrupted code is live if `mepcc` still has its tag; it is
      // resumed as if its handler had returned. A fault frame (fault.hpp)
      // only on the INSTALL_CONTEXT verdict of the handler that just
      // returned from it -- never one beneath, whose handler was itself
      // abandoned -- and with the context that handler left in its
      // ErrorState, which is read here, before the assembly zeroes the
      // handler's stack.
      bool resumable = capability_is_valid(f->mepcc);
      const bool fault = (f->flags & trap::TRAP_FLAG_FAULT) != 0;
      if (fault) {
        resumable = resumable && first &&
                    verdict == fault::INSTALL_CONTEXT &&
                    trap::install_context(f);
      }
      // `mret` sets MIE := MPIE, and the MPIE the hardware holds now is
      // stale if anything trapped or switched threads since the trap was
      // taken, so set it from the `mstatus` recorded then: the interrupted
      // code resumes with exactly the MIE it had. Only MPIE is touched here;
      // the trap vector forces MPP back to M just before its `mret`
      // (early_trap.S, step 5).
      if (resumable) {
        if ((f->mstatus & MSTATUS_MPIE) != 0) {
          __asm__ volatile("csrs mstatus, %0" : : "r"(MSTATUS_MPIE));
        } else {
          __asm__ volatile("csrc mstatus, %0" : : "r"(MSTATUS_MPIE));
        }
        return KIND_TRAP_FRAME;
      }
      if (fault) {
        // The faulting code is abandoned: whoever is beneath hears why
        // (Faulted, or CompartmentDestroyed if it was gone already).
        const uint64_t status = f->fault_status != 0
                                    ? f->fault_status
                                    : static_cast<uint64_t>(Status::Faulted);
        value = reinterpret_cast<Capability>(static_cast<uintptr_t>(status));
        faulted = true;
        continue;
      }
    }

    // The frame just skipped belonged to a compartment that is gone. Whoever
    // is beneath it is told so instead of getting a return value.
    value = reinterpret_cast<Capability>(
        static_cast<uintptr_t>(Status::CompartmentDestroyed));
  }
}

}  // namespace signetos::unwind
