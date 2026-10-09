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
 * sentry.cpp - SignetOS Compartment Entry Points
 *
 * See sentry.hpp. A sentry is an OType::EntryPoint-sealed pointer to an
 * EntryRecord {pcc, cgp, owner, flags, min_stack} living on the owner's entry
 * pages (or, for the kernel's own system calls, in `syscall.cpp`'s record
 * table).
 */

#include <stddef.h>
#include <signetos/asm_macros.h>
#include <signetos/compartment.hpp>
#include <signetos/inspect.hpp>
#include <signetos/sealing.hpp>
#include <signetos/sentry.hpp>
#include <signetos/thread.hpp>
#include <signetos/uart.hpp>
#include <signetos/unwind.hpp>
#include <signetos/vm.hpp>

namespace signetos::sentry {
namespace {

// The assembly switcher addresses the frame by these offsets.
static_assert(offsetof(ReturnFrame, prev_ksp) == FRAME_LINK);
static_assert(offsetof(ReturnFrame, tp) == RET_FRAME_TP);
static_assert(offsetof(ReturnFrame, args) == RET_FRAME_ARG0);
static_assert(offsetof(ReturnFrame, args) + 4 * sizeof(Capability) ==
              RET_FRAME_ARG4);
static_assert(offsetof(ReturnFrame, callee_sp) == RET_FRAME_CALLEE_SP);
static_assert(offsetof(ReturnFrame, callee_gp) == RET_FRAME_CALLEE_GP);
static_assert(offsetof(ReturnFrame, sstatus) == RET_FRAME_SSTATUS);
static_assert(offsetof(ReturnFrame, flags) == RET_FRAME_FLAGS);
static_assert(sizeof(ReturnFrame) == RET_FRAME_SIZE);
static_assert(ENTRY_FLAG_TRUSTED == ENTRY_TRUSTED);
static_assert(static_cast<uint64_t>(Status::NoKernelStack) ==
              STATUS_NO_KERNEL_STACK);
static_assert((DEFAULT_MIN_STACK & 0xF) == 0);

Capability s_root_code_cap = nullptr;

Capability create_impl(Capability comp, Capability code_cap,
                       uint64_t perms_mask, bool require_owned,
                       Status* out_status) {
  if (!capability_is_valid(code_cap) || sealing::is_sealed(code_cap)) {
    return fail_with(out_status, Status::InvalidCapability);
  }
  const uint64_t in_perms = capability_get_perms(code_cap);
  if ((in_perms & perms::Load) == 0) {
    return fail_with(out_status, Status::InsufficientPermission);
  }
  // Accept either an already-executable capability or a writable allocation
  // (e.g. from sys_vm_allocate) being transitioned into a W^X entry point.
  if ((in_perms & (perms::Execute | perms::Store)) == 0) {
    return fail_with(out_status, Status::NotExecutable);
  }
  // The record outlives the call: a local capability (a thread's stack, or
  // anything derived from one) is not allowed to be remembered by the kernel.
  if ((in_perms & perms::Global) == 0) {
    return fail_with(out_status, Status::InvalidCapability);
  }

  const uint64_t base = capability_get_base(code_cap);
  const uint64_t len = capability_get_length(code_cap);
  const uint64_t addr = capability_get_address(code_cap);

  if (len == 0 || len > MAX_ENTRY_LENGTH) {
    return fail_with(out_status, Status::Unbounded);
  }
  if (addr < base || (addr - base) >= len || (addr & 1u) != 0) {
    return fail_with(out_status, Status::BadAlignment);
  }

  // No compartment can own memory outside `[vm::DYNAMIC_BASE, vm::DYNAMIC_TOP)`.
  if (require_owned &&
      (base < vm::DYNAMIC_BASE || len > (vm::DYNAMIC_TOP - base))) {
    return fail_with(out_status, Status::NotOwned);
  }

  // Enforce W^X and least privilege:
  //   - For normal compartment entry points (`require_owned == true`, or any
  //     address in `[vm::DYNAMIC_BASE, vm::DYNAMIC_TOP)`), derive `rx` from
  //     `s_root_code_cap`, which is hardware-bounded to
  //     `[vm::DYNAMIC_BASE, vm::DYNAMIC_TOP)` with `perms::CodeRx`. Because
  //     `s_root_code_cap` does not cover `[0x80000000, 0x81000000)`, hardware
  //     bounds monotonicity makes it impossible for `sys_sentry` to mint an
  //     executable capability overlapping the kernel image.
  //   - Only for kernel-internal test entry points (`!require_owned` via
  //     `create_kernel` when `base < vm::DYNAMIC_BASE`), derive `rx` from the
  //     kernel's own bounded `PCC` (`[_kernel_start, _got_end)`).
  Capability code_root = s_root_code_cap;
  if (!require_owned && base < vm::DYNAMIC_BASE) {
    __asm__ volatile("auipcc %0, 0" : "=C"(code_root));
  }

  const uint64_t allowed = (perms_mask & perms::CodeRx) | perms::Execute;
  Capability rx = capability_set_address(code_root, base);
  rx = capability_set_bounds(rx, len);
  rx = capability_set_address(rx, addr);
  rx = capability_and_perms(rx, allowed);
  if (!capability_is_valid(rx) ||
      (capability_get_perms(rx) & (perms::Store | perms::Seal | perms::Unseal |
                                   perms::AccessSystemRegs)) != 0) {
    return fail_with(out_status, Status::SealFailed);
  }

  // Record {code, comp} on the owner's entry pages (checks ownership and bills
  // a fresh page to the owner's quota if the chain is full).
  compartment::Status c_status = compartment::Status::Ok;
  Capability record =
      compartment::add_entry(comp, rx, require_owned, &c_status);
  if (c_status != compartment::Status::Ok || !capability_is_valid(record)) {
    return fail_with(out_status, c_status);
  }

  __asm__ volatile("fence.i" ::: "memory");

  // The handle conveys nothing but the right to enter: Permit_Load if asked
  // for (invoke requires it), and nothing that could write the record.
  Capability handle = (perms_mask & perms::Load) != 0
                          ? handle_for(record)
                          : sealing::seal_as(OType::EntryPoint,
                                             capability_and_perms(record, 0));
  if (!capability_is_valid(handle)) {
    return fail_with(out_status, Status::SealFailed);
  }

  if (out_status != nullptr) {
    *out_status = Status::Ok;
  }
  return handle;
}

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
// cannot be used. Declared in sentry.hpp: the trap path uses it too.
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

void init(Capability root_data_cap) {
  // Derive `s_root_code_cap` bounded strictly to the dynamic compartment VA
  // window `[vm::DYNAMIC_BASE, vm::DYNAMIC_TOP)` with `perms::CodeRx` (W^X, no
  // Store, Seal, Unseal, or AccessSystemRegs).
  s_root_code_cap = nullptr;
  if (capability_is_valid(root_data_cap)) {
    Capability code = capability_set_address(root_data_cap, vm::DYNAMIC_BASE);
    code = capability_set_bounds(code, vm::DYNAMIC_TOP - vm::DYNAMIC_BASE);
    code = capability_and_perms(code, perms::CodeRx);
    if (capability_is_valid(code) &&
        capability_get_base(code) == vm::DYNAMIC_BASE &&
        capability_get_length(code) == vm::DYNAMIC_TOP - vm::DYNAMIC_BASE &&
        (capability_get_perms(code) &
         (perms::Store | perms::Seal | perms::Unseal |
          perms::AccessSystemRegs)) == 0) {
      s_root_code_cap = code;
    }
  }
  if (!capability_is_valid(s_root_code_cap)) {
    uart::panic("sentry: cannot derive the compartment code root");
  }
}

Capability create(Capability comp, Capability code_cap, uint64_t perms_mask,
                  Status* out_status) {
  return create_impl(comp, code_cap, perms_mask, true, out_status);
}

Capability create_kernel(Capability comp, Capability code_cap,
                         uint64_t perms_mask, Status* out_status) {
  return create_impl(comp, code_cap, perms_mask, false, out_status);
}

Sentry handle_for(Capability record) {
  if (!capability_is_valid(record) ||
      capability_get_length(record) != sizeof(EntryRecord)) {
    return nullptr;
  }
  Capability handle = capability_and_perms(
      record, perms::Load | perms::LoadCapability | perms::LoadMutable);
  return sealing::seal_as(OType::EntryPoint, handle);
}

Status resolve(Sentry entry_point, Entry* out) {
  *out = Entry{};
  if (!capability_is_valid(entry_point)) {
    return Status::InvalidCapability;
  }

  // Operational authority (Permit_Load) is required to invoke an entry point.
  if ((capability_get_perms(entry_point) & perms::Load) == 0) {
    return Status::InsufficientPermission;
  }

  Capability open = sealing::unseal_as(OType::EntryPoint, entry_point);
  if (!capability_is_valid(open) ||
      capability_get_length(open) != sizeof(EntryRecord)) {
    return Status::InvalidCapability;
  }
  if ((capability_get_perms(open) &
       (perms::Load | perms::LoadCapability)) !=
      (perms::Load | perms::LoadCapability)) {
    return Status::InsufficientPermission;
  }

  const EntryRecord* rec = reinterpret_cast<const EntryRecord*>(open);

  // Cleared record (owner destroyed): refuse. A compartment entry must also
  // still have its table and its owner; a kernel entry has neither.
  const Capability code = rec->pcc;
  const Capability table = rec->cgp;
  const Capability owner = rec->owner;
  const uint64_t flags = rec->flags;
  const bool trusted = (flags & ENTRY_FLAG_TRUSTED) != 0;
  if (!capability_is_valid(code) ||
      (!trusted &&
       (!capability_is_valid(table) || !capability_is_valid(owner)))) {
    return Status::InvalidCapability;
  }

  // Verify W^X and no privilege escalation before converting to a hardware
  // CT = 1 sentry for `cjalr`. Only the kernel's own entries run with ASR.
  const uint64_t forbidden =
      perms::Store | perms::Seal | perms::Unseal |
      (trusted ? 0 : perms::AccessSystemRegs);
  if ((capability_get_perms(code) & forbidden) != 0) {
    return Status::InvalidCapability;
  }

  Capability hw_sentry = sealing::seal_entry(code);
  if (!capability_is_valid(hw_sentry)) {
    return Status::InvalidCapability;
  }

  out->sentry = hw_sentry;
  out->table = trusted ? nullptr : table;
  out->owner = trusted ? nullptr : owner;
  out->flags = flags;
  out->min_stack = rec->min_stack;
  return Status::Ok;
}

Capability unseal(Sentry entry_point, Status* out_status) {
  Entry entry{};
  const Status status = resolve(entry_point, &entry);
  if (status != Status::Ok) {
    return fail_with(out_status, status);
  }
  if ((entry.flags & ENTRY_FLAG_TRUSTED) != 0) {
    return fail_with(out_status, Status::InvalidSentry);
  }
  if (out_status != nullptr) {
    *out_status = Status::Ok;
  }
  return entry.sentry;
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

  // Unseal `entry_point` (`OType::EntryPoint`, CT = 12), verify its owning
  // compartment is still live, and extract the `EntryRecord`'s `pcc` (sealed
  // as a `CT = 1` hardware sentry), `cgp`, flags and stack requirement.
  Entry entry{};
  Status status = resolve(entry_point, &entry);
  if (status != Status::Ok) {
    return refuse(status);
  }
  // `trusted` means a kernel syscall gate (syscall::gate); otherwise it's a
  // user compartment. Unmasked compartments can be interrupted at any time,
  // so ensure enough kernel stack remains for a trap frame and handler.
  const bool trusted = (entry.flags & ENTRY_FLAG_TRUSTED) != 0;
  if (!trusted && (frame->sstatus & SSTATUS_SIE) != 0 &&
      thread::kernel_stack_free(reinterpret_cast<Capability>(frame)) <
          TRAP_FRAME_SIZE + RET_FRAME_MIN_FREE) {
    return refuse(Status::NoKernelStack);
  }

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
    for (size_t i = 0; i < 5; ++i) {
      inspect::assert_user_capability(frame->args[i], "switcher_prepare:arg");
    }
  }

  frame->callee_sp = narrowed;
  frame->callee_gp = entry.table;
  if (trusted) {
    entry.flags |= ENTRY_FLAG_TRUSTED_TO_FINISH;  // the kernel always finishes
  } else if (entry.owner != nullptr) {
    const auto* c =
        reinterpret_cast<const compartment::Compartment*>(entry.owner);
    if ((__atomic_load_n(&c->flags, __ATOMIC_ACQUIRE) &
         compartment::FLAG_TRUSTED_TO_FINISH) != 0) {
      entry.flags |= ENTRY_FLAG_TRUSTED_TO_FINISH;
    }
  }
  frame->flags = entry.flags;
  thread::set_kernel_sp(reinterpret_cast<Capability>(frame));
  return entry.sentry;
}

extern "C" uint64_t __signetos_switcher_return(Capability ret) {
  // Pop the callee's `ReturnFrame`, scrub the stack it ran on and hand `ret`
  // to the caller -- or, if the caller's compartment has been destroyed and
  // swept since the call, to the nearest live frame beneath (unwind.hpp).
  // The top frame must be a `ReturnFrame`, so a stashed/replayed `cra`
  // return sentry cannot underflow the kernel stack or confuse a `TrapFrame`
  // for a `ReturnFrame`. The assembly resumes whatever kind of frame this
  // stops at.
  return unwind::resume(unwind::KIND_RETURN_FRAME, ret);
}

Status invoke(Sentry entry_point, uint64_t arg0, uint64_t* out_result) {
  Status status = Status::Ok;
  Capability hw_sentry = unseal(entry_point, &status);
  if (status != Status::Ok || !capability_is_valid(hw_sentry)) {
    return status;
  }

  using EntryFn = uint64_t (*)(uint64_t);
  EntryFn fn = reinterpret_cast<EntryFn>(hw_sentry);
  const uint64_t result = fn(arg0);

  if (out_result != nullptr) {
    *out_result = result;
  }
  return Status::Ok;
}

}  // namespace signetos::sentry
