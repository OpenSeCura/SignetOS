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
 * switcher.cpp - The C half of the domain switcher (switcher.hpp; the
 * assembly half is switch.S)
 */

#include <stddef.h>

#include <signetos/asm_macros.h>
#include <signetos/debug/inspect.hpp>
#include <signetos/sealing.hpp>
#include <signetos/sentry.hpp>
#include <signetos/switcher.hpp>
#include <signetos/thread.hpp>
#include <signetos/trap.hpp>
#include <signetos/unwind.hpp>

namespace signetos::switcher {
namespace {

using sentry::Entry;
using sentry::ENTRY_FLAG_TRUSTED;
using sentry::resolve;

// The assembly switcher addresses the frame by these offsets.
static_assert(offsetof(ReturnFrame, prev_ksp) == FRAME_LINK);
static_assert(offsetof(ReturnFrame, tp) == RET_FRAME_TP);
static_assert(offsetof(ReturnFrame, args) == RET_FRAME_ARG0);
static_assert(offsetof(ReturnFrame, args) + 4 * sizeof(Capability) ==
              RET_FRAME_ARG4);
static_assert(offsetof(ReturnFrame, callee_sp) == RET_FRAME_CALLEE_SP);
static_assert(offsetof(ReturnFrame, callee_gp) == RET_FRAME_CALLEE_GP);
static_assert(offsetof(ReturnFrame, mstatus) == RET_FRAME_MSTATUS);
static_assert(offsetof(ReturnFrame, flags) == RET_FRAME_FLAGS);
static_assert(offsetof(ReturnFrame, callee_comp) == RET_FRAME_CALLEE_COMP);
static_assert(sizeof(ReturnFrame) == RET_FRAME_SIZE);
static_assert(ENTRY_FLAG_TRUSTED == ENTRY_TRUSTED);
static_assert(static_cast<uint64_t>(Status::NoKernelStack) ==
              STATUS_NO_KERNEL_STACK);

}  // namespace

// The permissions a stack capability must carry for anyone -- the callee or
// the kernel -- to run on it: loads and stores of data and capabilities,
// capabilities loaded back with their Store permission intact (LoadMutable),
// local capabilities storable (StoreLocal: spilled stack pointers are local)
// and loaded back as they were (LoadGlobal). A capability without StoreLocal
// is by construction not a thread stack (`compartment::allocate` and the
// capability table withhold it), so this check is also what keeps the kernel
// from ever running on memory another thread can reach.
constexpr uint64_t kStackPerms = perms::Load | perms::Store |
                                 perms::LoadCapability |
                                 perms::StoreCapability | perms::LoadMutable |
                                 perms::StoreLocal | perms::LoadGlobal;

Capability narrow_stack(Capability caller_sp, uint64_t min_stack,
                        Status* out_status) {
  if (!capability_is_valid(caller_sp) || sealing::is_sealed(caller_sp)) {
    *out_status = Status::InvalidCapability;
    return nullptr;
  }
  const uint64_t sp_perms = capability_get_perms(caller_sp);
  if ((sp_perms & kStackPerms) != kStackPerms ||
      (sp_perms & perms::Execute) != 0) {
    *out_status = Status::InsufficientPermission;
    return nullptr;
  }

  const uint64_t base = capability_get_base(caller_sp);
  const uint64_t addr = capability_get_address(caller_sp);
  const uint64_t top = base + capability_get_length(caller_sp);
  if (addr <= base || addr > top || (base & 0xFULL) != 0 ||
      (addr & 0xFULL) != 0) {
    *out_status = Status::BadAlignment;
    return nullptr;
  }
  if (addr - base < min_stack) {
    *out_status = Status::StackTooSmall;
    return nullptr;
  }
  const uint64_t lo = base;

  // For large regions, `csetbounds` (`scbndsr`) rounds the length up if `lo`
  // or the length is not aligned to the representable alignment mask. Round
  // `lo` up and `addr` down to `mask` so `[aligned_lo, aligned_top)` is
  // strictly inside `[lo, addr)` and never overlaps the caller's frame.
  const size_t mask = __builtin_cheri_representable_alignment_mask(
      static_cast<size_t>(addr - lo));
  const uint64_t aligned_lo = (lo + ~mask) & mask;
  const uint64_t aligned_top = addr & mask;
  if (aligned_top <= aligned_lo || aligned_top - aligned_lo < min_stack) {
    *out_status = Status::StackTooSmall;
    return nullptr;
  }
  Capability narrowed = capability_set_address(caller_sp, aligned_lo);
  narrowed = capability_set_bounds(narrowed,
                                   static_cast<size_t>(aligned_top - aligned_lo));
  const uint64_t narrowed_top =
      capability_get_base(narrowed) + capability_get_length(narrowed);
  if (!capability_is_valid(narrowed) || narrowed_top > addr ||
      (narrowed_top & 0xFULL) != 0) {
    *out_status = Status::BadAlignment;
    return nullptr;
  }
  return capability_set_address(narrowed, narrowed_top);
}

static Capability active_slice(Capability ksp) {
  // A fault handler runs inside the slice of the code that faulted.
  while (unwind::kind_at(ksp) == unwind::KIND_TRAP_FRAME) {
    ksp = reinterpret_cast<const trap::TrapFrame*>(ksp)->active_kernel_sp;
  }
  return unwind::kind_at(ksp) == unwind::KIND_RETURN_FRAME
             ? reinterpret_cast<const ReturnFrame*>(ksp)->callee_sp
             : thread::current_initial_sp();
}

Capability slice_below(Capability stack, uint64_t ceiling, uint64_t bytes,
                       Status* out_status) {
  // Rounded so the bounds come out exact.
  const size_t len =
      __builtin_cheri_round_representable_length((bytes + 0xF) & ~0xFULL);
  const uint64_t top =
      ceiling & __builtin_cheri_representable_alignment_mask(len);
  const uint64_t base = capability_get_base(stack);
  if (!capability_is_valid(stack) || bytes == 0 || top < base ||
      top - base < len) {
    *out_status = Status::StackTooSmall;
    return nullptr;
  }
  Capability slice =
      capability_set_bounds(capability_set_address(stack, top - len), len);
  return capability_set_address(slice, top);
}

static Capability next_slice(Capability ksp, uint64_t bytes,
                             Status* out_status) {
  const Capability active = active_slice(ksp);
  if (!capability_is_valid(active)) {
    *out_status = Status::InvalidCapability;
    return nullptr;
  }
  return slice_below(thread::current_user_stack(),
                     capability_get_base(active), bytes, out_status);
}

// True if `cap` overlaps the thread's stack below address `limit`.
static bool into_stack(Capability cap, uint64_t limit) {
  const Capability stack = thread::current_user_stack();
  if (!capability_is_valid(cap) || !capability_is_valid(stack)) {
    return false;
  }
  const uint64_t stack_lo = capability_get_base(stack);
  const uint64_t stack_hi = stack_lo + capability_get_length(stack);
  const uint64_t lo = capability_get_base(cap);
  const uint64_t len = capability_get_length(cap);
  const uint64_t hi = len == 0 ? lo + 1 : lo + len;  // may wrap
  return lo < (limit < stack_hi ? limit : stack_hi) &&
         (hi < lo || hi > stack_lo);
}

extern "C" Capability __signetos_switcher_prepare(Sentry entry_point,
                                                  ReturnFrame* frame) {
  if (frame == nullptr) {
    return nullptr;
  }
  auto refuse = [&](Status s) -> Capability {
    frame->args[0] =
        reinterpret_cast<Capability>(static_cast<uintptr_t>(s));
    return nullptr;
  };

  // Unseal `entry_point` (`OType::EntryPoint`, CT = 18), verify its owning
  // compartment is still live, and extract the `EntryRecord`'s `pcc` (sealed
  // as a `CT = 1` hardware sentry), `cgp`, flags and stack requirement.
  Entry entry{};
  Status status = resolve(entry_point, &entry);
  if (status != Status::Ok) {
    return refuse(status);
  }
  // `trusted` means a kernel syscall gate (syscall::gate); otherwise it's a
  // user compartment.
  const bool trusted = (entry.flags & ENTRY_FLAG_TRUSTED) != 0;

  // The callee's slice: `min_stack` bytes directly below the caller's.
  Capability narrowed = nullptr;
  if (entry.min_stack != 0) {
    narrowed = next_slice(frame->prev_ksp, entry.min_stack, &status);
    if (!capability_is_valid(narrowed)) {
      return refuse(status);
    }
  } else if (!trusted) {
    return refuse(Status::InvalidSentry);  // a compartment entry always has one
  }

  // Domain switcher entry: verify that every capability about to be loaded into a compartment
  // callee's register file (`ct0 = sentry`, `cgp = table`, `csp = narrowed`,
  // `ca0..ca4 = args[0..4]`) is restricted, obeys W^X, carries no
  // sealing/unsealing authority, and does not overlap kernel memory. A kernel
  // entry's arguments go to the kernel and are not checked.
  inspect::assert_user_capability(entry.sentry, "switcher_prepare:sentry");
  inspect::assert_user_capability(entry.table, "switcher_prepare:callee_gp");
  inspect::assert_user_capability(narrowed, "switcher_prepare:callee_sp");
  if (!trusted) {
    // Code never crosses a compartment boundary, only entry points do
    // (DESIGN.md §2.5): a call carrying code, plain or a sentry, is refused.
    for (size_t i = 0; i < 5; ++i) {
      if (inspect::is_user_code(frame->args[i])) {
        return refuse(Status::InvalidCapability);
      }
    }
    // A lent stack buffer cannot be given stack pointers: the callee could
    // leave one to its own slice there, outliving the slice.
    for (size_t i = 0; i < 5; ++i) {
      if (into_stack(frame->args[i], ~0ULL)) {
        frame->args[i] =
            capability_and_perms(frame->args[i], ~perms::StoreLocal);
      }
      inspect::assert_user_capability(frame->args[i], "switcher_prepare:arg");
    }
  }

  // Zeroed below its top by the assembly before a compartment callee is
  // entered (switch.S, STACK ZEROING); a kernel callee is not given anything
  // it could leak.
  frame->callee_sp = narrowed;
  frame->callee_gp = entry.table;
  // Whose code this call enters: what the trap dispatcher reads to tell which
  // compartment faulted, when this frame is the one under a fault's
  // `TrapFrame` (trap.hpp, WHO FAULTED). Null for a kernel entry.
  frame->callee_comp = entry.owner;
  // The callee's flags, for the unwinder and the trap path: whether the
  // code above this frame is the kernel (ENTRY_FLAG_TRUSTED).
  frame->flags = entry.flags;
  thread::set_kernel_sp(reinterpret_cast<Capability>(frame));
  return entry.sentry;
}

extern "C" uint64_t __signetos_switcher_return(Capability ret) {
  // Pop the callee's `ReturnFrame` and hand `ret` to the caller (the
  // assembly then zeroes the stack the callee ran on) -- or, if the caller's
  // compartment has been destroyed and swept since the call, to the nearest
  // live frame beneath (unwind.hpp).
  // The top frame must be a `ReturnFrame`, so a stashed/replayed `cra`
  // return sentry cannot underflow the kernel stack or confuse a `TrapFrame`
  // for a `ReturnFrame`. The assembly resumes whatever kind of frame this
  // stops at.
  //
  // Code never crosses a compartment boundary (DESIGN.md §2.5), so code
  // returned by the callee reaches the caller as `InvalidCapability`.
  // Nor does a pointer into the callee's slice, which is about to be reused.
  const Capability ksp = thread::current_kernel_sp();
  bool into_callee = false;
  if (unwind::kind_at(ksp) == unwind::KIND_RETURN_FRAME) {
    const Capability slice = reinterpret_cast<const ReturnFrame*>(ksp)->callee_sp;
    into_callee = into_stack(ret, capability_get_base(slice) +
                                      capability_get_length(slice));
  }
  if (inspect::is_user_code(ret)) {
    ret = reinterpret_cast<Capability>(
        static_cast<uintptr_t>(Status::InvalidCapability));
  } else if (into_callee) {
    ret = reinterpret_cast<Capability>(
        static_cast<uintptr_t>(Status::StackCapability));
  }
  return unwind::resume(unwind::KIND_RETURN_FRAME, ret);
}

}  // namespace signetos::switcher
