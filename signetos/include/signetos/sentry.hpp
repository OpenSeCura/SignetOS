/*
 * Copyright 2026 Google LLC (Cherified Team)
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
// Implements design_spec.md section 2.5 (capability_sentry_t) and section 5.4
// (sys_sentry / sys_compartment_invoke).
//
// WHY TWO HARDWARE TYPES ARE USED (CT = 12 vs CT = 1)
// ---------------------------------------------------
// CHERI RISC-V with Zyseal provides two distinct sealing mechanisms:
//
//   1. `sentry` (CT = 1, OType::Sentry):
//      Ambient (unprivileged) instruction. Automatically unsealed into PCC by
//      `cjalr`. The only CT = 1 sentry a compartment holds is the switcher
//      itself (`sys_compartment_invoke`); the switcher also uses CT = 1 for
//      its final branch into a callee.
//
//   2. `yseal` with OType::EntryPoint (CT = 12):
//      Authority-gated instruction requiring the kernel's `g_type_root`.
//      Cannot be produced by user compartments, cannot be dereferenced, and
//      CANNOT be jumped to directly by `cjalr` (which only unseals CT = 1).
//
// WHAT A SENTRY POINTS AT
// -----------------------
// `sys_sentry(comp, code)` validates `code`, strips write/seal/ASR permissions
// to `perms::CodeRx` (W^X), checks that `code` lies in `comp`'s own memory,
// and writes `{pcc, cgp, owner, flags, min_stack}` into an `EntryRecord` on
// one of `comp`'s entry pages (billed to `comp`'s funding quota). The sentry
// is that record's address, sealed as `OType::EntryPoint` (CT = 12).
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
// way in, interrupts stay masked, the callee's stack is exactly `min_stack`
// bytes of the caller's, and the callee's `a0` comes back to the caller. Only
// `syscall::gate` ever sets it; `sys_sentry` records are never trusted, and
// `sys_thread_create` / `sys_trap_bind` refuse trusted entries.
constexpr uint64_t ENTRY_FLAG_TRUSTED = 1u << 0;

// Stack a `sys_sentry` entry is promised: the switcher refuses a call whose
// caller has less than this free below `csp`, so a callee is never entered on
// a stack too small to run its prologue and fault half way through an update.
constexpr uint64_t DEFAULT_MIN_STACK = 2048;

// An entry on one of a compartment's entry pages. A sentry is a sealed pointer
// to one of these.
//
// Entry pages share the range-page header (`next`, `funder`) and are billed to
// the compartment's funding quota when no free record remains.
struct alignas(16) EntryRecord {
  Capability pcc;      // CodeRx entry point, unsealed; null means the record is free
  Capability cgp;      // the owning compartment's writable capability table slice
                       // (null for a kernel entry: kernel code never uses cgp)
  Capability owner;    // the owning compartment's page (kernel capability), so
                       // whoever enters through this record can be counted
                       // into it (compartment.hpp, WHO IS INSIDE). Null for a
                       // kernel entry: the kernel is not a compartment.
  uint64_t flags;      // ENTRY_FLAG_*
  uint64_t min_stack;  // bytes the caller must have free below csp; a trusted
                       // entry runs on exactly this much. 16-byte multiple.
};

constexpr size_t ENTRY_PAGE_HEADER = 2 * sizeof(Capability);
constexpr size_t ENTRIES_PER_PAGE =
    (vm::PAGE_SIZE - ENTRY_PAGE_HEADER) / sizeof(EntryRecord);

static_assert(sizeof(EntryRecord) == 4 * sizeof(Capability),
              "an entry record is exactly four capability slots");
static_assert(ENTRY_PAGE_HEADER + ENTRIES_PER_PAGE * sizeof(EntryRecord) <=
                  vm::PAGE_SIZE,
              "the header plus the entry records must fit in a page");

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


// Core of sys_sentry. Validates `code_cap`, strips permissions down to
// `(perms_mask & perms::CodeRx)` (W^X, no Seal/Unseal/ASR), requires it to lie
// inside `comp`'s memory, records it on `comp`'s entry pages, and returns the
// sealed record pointer.
//
// The returned handle carries Permit_Load only if `perms_mask` does; invoking
// requires it.
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
Capability handle_for(Capability record);

// What an `OType::EntryPoint` handle resolves to.
struct Entry {
  Capability sentry;   // CT = 1 hardware sentry for the record's `pcc`
  Capability table;    // the callee's `cgp` (null for a kernel entry)
  Capability owner;    // the callee's compartment page (null for a kernel entry)
  uint64_t flags;      // EntryRecord::flags
  uint64_t min_stack;  // EntryRecord::min_stack
};

// Authenticates an `OType::EntryPoint` handle, verifies Permit_Load and that
// its record is still there, and fills `*out`. Whether the owning compartment
// will still be there when the callee runs is `compartment::enter`'s question,
// asked by whoever is about to run it.
Status resolve(Capability handle, Entry* out);

// resolve() for a compartment entry: returns the hardware `CT = 1` sentry, or
// null (and `*out_status`) if `handle` is not a live, invokable compartment
// entry. Kernel entries (`ENTRY_FLAG_TRUSTED`) are refused: they are only ever
// entered through the switcher, never bound to a trap or started as a thread.
Capability unseal(Capability handle, Status* out_status = nullptr);

// Saved caller context pushed onto a thread's kernel stack across a
// synchronous `sys_compartment_invoke` call. Layout matches `asm_macros.h`.
struct alignas(16) ReturnFrame {
  Capability ra;         //   0: caller return address (cra)
  Capability sp;         //  16: caller stack pointer (csp, full bounds)
  Capability gp;         //  32: caller capability table (cgp)
  Capability tp;         //  48: caller thread pointer (ctp)
  Capability s[12];      //  64..240: caller callee-saved registers (cs0..cs11)
  Capability prev_ksp;   // 256: previous per-hart `sscratchc` kernel SP
  Capability args[5];    // 272..336: caller's ca1..ca5, the callee's ca0..ca4
                         //      (a compartment callee gets args[0] only).
                         //      args[0] is reused for what the caller gets
                         //      back in ca0: the kernel's return value, the
                         //      Status of a refused call, or null.
  Capability callee_sp;  // 352: narrowed stack capability for callee
  Capability callee_gp;  // 368: capability table for callee
  uint64_t sstatus;      // 384: caller's `sstatus` at entry (SIE restored on
                         //      return and propagated to a compartment callee)
  uint64_t flags;        // 392: EntryRecord::flags of the callee
};

static_assert(sizeof(ReturnFrame) == 25 * sizeof(Capability),
              "ReturnFrame must be 25 capability slots (400 bytes)");

// Helpers called by the assembly domain switcher (`sys_compartment_invoke`):
//   - `__signetos_switcher_prepare` validates `handle` and the caller's `csp`,
//     narrows the stack for the callee (everything below `csp` for a
//     compartment, exactly `min_stack` bytes for a kernel entry), populates
//     `frame->callee_sp`, `frame->callee_gp` and `frame->flags`, advances the
//     hart's `sscratchc` kernel SP to `frame`, and returns the callee's
//     `CT = 1` hardware sentry. On refusal it returns null and leaves the
//     `Status` (as an integer) in `frame->args[0]` for the caller.
//   - `__signetos_switcher_return` validates and pops the top `ReturnFrame`
//     from the hart's `sscratchc` kernel SP, scrubs the callee's stack region
//     (the bounds of `callee_sp`), stores what the caller gets back in
//     `frame->args[0]` (`ret`, checked, for a kernel entry; null for a
//     compartment), and returns the popped `ReturnFrame*` (or null if the
//     return sentry was replayed on an empty/mismatched stack).
extern "C" Capability __signetos_switcher_prepare(Capability handle,
                                                  ReturnFrame* frame);
extern "C" ReturnFrame* __signetos_switcher_return(Capability ret);

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
// to the stack a bound handler gets (`__signetos_trap_dispatch`).
Capability narrow_stack(Capability caller_sp, uint64_t min_stack,
                        uint64_t want, Status* out_status);


// Validates `handle` via `unseal()` and transfers control to its entry point
// directly (kernel-internal; no domain switch).
Status invoke(Capability handle, uint64_t arg0, uint64_t* out_result = nullptr);


}  // namespace signetos::sentry
