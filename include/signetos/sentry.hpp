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
// sentry.hpp - SignetOS Compartment Entry Points
//
// WHY TWO HARDWARE TYPES ARE USED (CT = 18 vs CT = 1)
// ---------------------------------------------------
// CHERI RISC-V with Zyseal provides two distinct sealing mechanisms:
//
//   1. Call sentry (CT = 1, OType::Sentry):
//      Made only by the kernel, with `yseal` under the call sentry authority
//      (sealing::seal_entry, toolchain/sentries). Unsealed into PCC by
//      `cjalr`. The only CT = 1 sentry a compartment holds is the switcher
//      itself (`sys_compartment_invoke`). The kernel also makes one for each
//      jump into a compartment (a callee, a new thread, a fault handler) and
//      jumps with `cjalr cra, cra`, so the link replaces it.
//
//   2. `yseal` with OType::EntryPoint (CT = 18):
//      Authority-gated instruction requiring the kernel's `g_type_root`.
//      Cannot be produced by user compartments, cannot be dereferenced, and
//      CANNOT be jumped to directly by `cjalr` (which only unseals sentries).
//
// WHAT A SENTRY POINTS AT
// -----------------------
// `sys_sentry(comp, code)` validates `code`, strips write/seal/ASR permissions
// to `perms::CodeRx` (W^X), checks that `code` lies in `comp`'s own memory,
// and writes `{pcc, cgp, owner, flags, min_stack}` into an `EntryRecord` on
// one of `comp`'s entry pages (billed to `comp`'s funding quota). The sentry
// is that record's address, sealed as `OType::EntryPoint` (CT = 18).
//
// Entering through it (`sys_compartment_invoke`, `sys_thread_create`) unseals
// the record, loads `pcc` to jump to, and loads `cgp` (the compartment's
// writable capability table) -- so the callee always starts with its own
// table, with no search and no second indirection.
//
// KERNEL ENTRIES
// --------------
// The kernel's own system calls are entry records too (`syscall::gate`), with
// `ENTRY_FLAG_TRUSTED` set: the switcher passes the caller's `a1..a4` through
// as the kernel's `a0..a3`, keeps interrupts masked, hands the kernel exactly
// `min_stack` bytes of the caller's stack, and returns the kernel's `a0`. One
// switcher, one frame layout, one scrub path for both kinds of callee.
//
// Destroying `comp` clears its records, so outstanding sentries stop
// resolving.
//

#include <stdint.h>
#include <signetos/types.hpp>
#include <signetos/vm.hpp>

namespace signetos::sentry {

// `EntryRecord::flags`.
//
// ENTRY_FLAG_TRUSTED marks a kernel entry. The switcher treats the callee as
// the kernel: arguments pass through in registers, nothing is scrubbed on the
// way in, interrupts stay masked, the callee's stack is a `min_stack` slice,
// and the callee's `a0` comes back to the caller. Only
// `syscall::gate` ever sets it; `sys_sentry` records are never trusted, and
// `sys_thread_create` refuses trusted entries.
constexpr uint64_t ENTRY_FLAG_TRUSTED = 1u << 0;

// The stack slice a `sys_sentry` entry runs on (switcher.hpp, STACK SLICES).
constexpr uint64_t DEFAULT_MIN_STACK = 8192;

// Room a fault handler needs below the faulting `csp`, in the same slice.
constexpr uint64_t FAULT_MIN_STACK = 1024;

// An entry on one of a compartment's entry pages. A sentry is a sealed pointer
// to one of these.
//
// Entry pages start with a compartment::PageHeader (`next`, `funder`) and are
// billed to the compartment's funding quota when no free record remains.
struct alignas(16) EntryRecord {
  Capability pcc;      // CodeRx entry point, unsealed; null means the record is free
  Capability cgp;      // the owning compartment's writable capability table slice
                       // (null for a kernel entry: kernel code never uses cgp)
  Capability owner;    // the owning compartment's canonical sealed handle
                       // (`compartment::handle_of`), read through
                       // `compartment::open`: which compartment the record
                       // belongs to. Null for a kernel entry: the kernel is not
                       // a compartment.
  uint64_t flags;      // ENTRY_FLAG_*
  uint64_t min_stack;  // bytes the caller must have free below csp; a trusted
                       // entry runs on exactly this much. 16-byte multiple.
};

static_assert(sizeof(EntryRecord) == 4 * sizeof(Capability),
              "an entry record is exactly four capability slots");

using Status = signetos::Status;
using signetos::status_name;

// Largest bounds accepted for a compartment entry point (16 MiB). Rejects
// unbounded capabilities (such as a raw `auipcc` spanning 2^64-1 bytes).
constexpr uint64_t MAX_ENTRY_LENGTH = 16u << 20;

// Initializes the sentry subsystem: derives a `perms::CodeRx` root code
// capability bounded strictly to the dynamic compartment address space
// `[vm::DYNAMIC_BASE, vm::DYNAMIC_TOP)` from `root_data_cap` and verifies the
// `OType::EntryPoint` sealing authority.
void init(Capability root_data_cap);


// The code capability compartment code may run with, made from `code_cap`:
// bounded (at most MAX_ENTRY_LENGTH), at an even address inside its bounds,
// inside the dynamic address space, and re-derived from the compartment code
// root with `CodeRx` only (W^X, no Seal/Unseal/ASR). Unsealed. Null (and
// `*out_status`) if `code_cap` cannot be one. Whether it lies in a particular
// compartment's memory is the caller's check (`compartment::add_entry`,
// `compartment::install_fault_handler`).
Capability entry_code(Capability code_cap, Status* out_status = nullptr);

// Core of sys_sentry. Makes `code_cap` an entry's code (`entry_code`, with
// permissions further limited to `perms_mask`), requires it to lie inside
// `comp`'s memory and records it on `comp`'s entry pages. Returns the sealed
// record pointer, which carries Permit_Load only if `perms_mask` does
// (invoking requires it).
Capability create(Capability comp, Capability code_cap,
                  uint64_t perms_mask = perms::CodeRx,
                  Status* out_status = nullptr);

// Kernel-internal only: as create(), but skips the ownership check so an entry
// point can be minted over kernel text (tests, boot). Never reachable from a
// syscall.
Capability create_kernel(Capability comp, Capability code_cap,
                         uint64_t perms_mask = perms::CodeRx,
                         Status* out_status = nullptr);

// Seals `record` (a kernel capability bounded to exactly one `EntryRecord`)
// into the `OType::EntryPoint` handle a compartment holds: Permit_Load only,
// so the holder can invoke it and nothing else. Used by `compartment::add_entry`
// for compartment entries and by `syscall::gate` for kernel entries.
Sentry handle_for(Capability record);

// What an `OType::EntryPoint` handle resolves to, and what the trap
// dispatcher enters a fault handler with (`compartment::fault_entry`).
struct Entry {
  Capability sentry;   // CT = 1 hardware sentry for the record's `pcc`
  Capability table;    // the callee's `cgp` (null for a kernel entry)
  Capability owner;    // the callee's compartment handle (null for a kernel
                       // entry); live when `resolve` returned
  uint64_t flags;      // EntryRecord::flags
  uint64_t min_stack;  // EntryRecord::min_stack
};

// Authenticates an `OType::EntryPoint` handle, verifies Permit_Load, that its
// record is still there and that its owner is a live compartment, and fills
// `*out`. Nothing keeps the owning compartment alive while the callee runs:
// if it is destroyed and swept in the meantime, the return into it is
// resolved by `unwind::resume`.
Status resolve(Sentry entry_point, Entry* out);

}  // namespace signetos::sentry
