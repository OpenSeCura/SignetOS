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
#include <signetos/compartment.hpp>
#include <signetos/sealing.hpp>
#include <signetos/sentry.hpp>
#include <signetos/debug/report.hpp>
#include <signetos/vm.hpp>

namespace signetos::sentry {
namespace {

static_assert((DEFAULT_MIN_STACK & 0xF) == 0);

Capability s_root_code_cap = nullptr;

// `entry_code`, with permissions limited to `perms_mask` as well, and, unless
// `require_owned`, allowed over kernel text (`create_kernel`).
Capability make_code(Capability code_cap, uint64_t perms_mask,
                     bool require_owned, Status* out_status) {
  if (!capability_is_valid(code_cap) || sealing::is_sealed(code_cap)) {
    return fail_with(out_status, Status::InvalidCapability);
  }
  const uint64_t in_perms = capability_get_perms(code_cap);
  if ((in_perms & perms::Load) == 0) {
    return fail_with(out_status, Status::InsufficientPermission);
  }
  // Accept either an already-executable capability or a writable allocation
  // (e.g. from sys_vm_allocate) being transitioned into a W^X entry point.
  // TODO: let's revisit this at a later time
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

  // No compartment can own memory outside `[vm::DYNAMIC_BASE,
  // vm::DYNAMIC_TOP)`. That range is the one we currently give to user
  // compartments
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
  return rx;
}

Capability create_impl(Capability comp, Capability code_cap,
                       uint64_t perms_mask, bool require_owned,
                       Status* out_status) {
  const Capability rx =
      make_code(code_cap, perms_mask, require_owned, out_status);
  if (!capability_is_valid(rx)) {
    return nullptr;
  }

  // Record {code, comp} on the owner's entry pages (checks ownership and bills
  // a fresh page to the owner's quota if the chain is full).
  compartment::Status c_status = compartment::Status::Ok;
  Capability record = compartment::add_entry(comp, rx, require_owned,
                                             DEFAULT_MIN_STACK, &c_status);
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
    reinterpret_cast<EntryRecord*>(record)->pcc = nullptr;  // free it again
    return fail_with(out_status, Status::SealFailed);
  }

  if (out_status != nullptr) {
    *out_status = Status::Ok;
  }
  return handle;
}

}  // namespace

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
    debug::panic("sentry: cannot derive the compartment code root");
  }
}

Capability entry_code(Capability code_cap, Status* out_status) {
  return make_code(code_cap, perms::CodeRx, true, out_status);
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

  // The owner must still be live. Destroy clears the records too, but this
  // also covers a record read just before that, and it is what lets every
  // reader of `Entry::owner` rely on it.
  if (!trusted && compartment::open(owner) == nullptr) {
    return Status::InvalidCompartment;
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

}  // namespace signetos::sentry
