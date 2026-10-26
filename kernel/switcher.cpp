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

// Validates the caller's stack capability and returns the stack the callee
// gets: `[addr - want, addr)` if `want` is non-zero, else everything below
// the caller's address, `[base, addr)`. Either way the result is at least
// `min_stack` bytes, 16-byte aligned at both ends, exactly representable (so
// `csetbounds` cannot round it up into the caller's live frames), and
// positioned at its own top. Null (and `*out_status`) if the caller's stack
// cannot be used. The trap path uses it too (switcher.hpp).
Capability narrow_stack(Capability caller_sp, uint64_t min_stack,
                        uint64_t want, Status* out_status) {
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
  if (addr - base < min_stack || addr - base < want) {
    *out_status = Status::StackTooSmall;
    return nullptr;
  }
  const uint64_t lo = want != 0 ? addr - want : base;

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

  // The callee's stack is carved out of the caller's, below the caller's
  // current `csp`, so CHERI monotonicity guarantees the callee cannot reach
  // the caller's live frames at `[addr, top)`. A compartment gets everything
  // below `csp` (it may need any amount); the kernel gets exactly the
  // `min_stack` bytes its system calls are sized for, so what it touches --
  // and what `__signetos_switcher_return` has to scrub -- is bounded.
  Capability narrowed = nullptr;
  if (entry.min_stack != 0) {
    narrowed = narrow_stack(frame->sp, entry.min_stack,
                            trusted ? entry.min_stack : 0, &status);
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
    for (size_t i = 0; i < 5; ++i) {
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
  if (inspect::is_user_code(ret)) {
    ret = reinterpret_cast<Capability>(
        static_cast<uintptr_t>(Status::InvalidCapability));
  }
  return unwind::resume(unwind::KIND_RETURN_FRAME, ret);
}

}  // namespace signetos::switcher
