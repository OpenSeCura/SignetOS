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
// syscall.hpp - SignetOS microkernel system call interface
//
// The complete kernel ABI: design_spec.md section 5, all 25 calls, spec-exact
// names and signatures. Nothing outside this header is reachable by a
// compartment.
//
// Calls are `extern "C"` because they are reached by jumping through a sealed
// sentry held in the caller's capability table, so the symbol names must be
// stable and unmangled.
//
// Handle types are all `void*` at the machine level; CHERI does not distinguish
// them. The distinct typedefs exist so a signature says which object type the
// hardware CT field is expected to carry.
//

#include <stdint.h>
#include <stddef.h>
#include <signetos/types.hpp>

// --- Handle types (design_spec.md section 2) -------------------------------

using capability_t             = signetos::Capability;  // any memory capability
using capability_data_t        = signetos::Capability;  // non-executable memory
using capability_exec_t        = signetos::Capability;  // executable, unsealed

using capability_quota_vm_t         = signetos::Capability;  // OTYPE_QUOTA_VM
using capability_quota_thread_mem_t = signetos::Capability;  // OTYPE_QUOTA_THREAD_MEM
using capability_compartment_t      = signetos::Capability;  // OTYPE_COMPARTMENT
using capability_thread_t           = signetos::Capability;  // OTYPE_THREAD
using capability_revoker_t          = signetos::Capability;  // OTYPE_REVOKER
using capability_sentry_t           = signetos::Capability;  // OTYPE_SENTRY
using capability_type_t             = signetos::Capability;  // OTYPE_TYPE_KEY
using capability_sealed_t           = signetos::Capability;  // OTYPE_SEALED_OBJECT

// --- sys_vm_allocate flags (design_spec.md section 5.1) --------------------

constexpr uint32_t FLAG_PINNED = (1u << 0);  // never swapped or migrated
constexpr uint32_t FLAG_ZERO   = (1u << 1);  // zero the pages before returning
constexpr uint32_t NO_ALIAS    = (1u << 2);  // refuse if the range is already mapped

extern "C" {

// --- 5.1 Virtual memory ----------------------------------------------------

// Allocates `size` bytes (rounded to page granularity), debits `mem_quota`,
// tags the mapping to `comp`. Returns a bounded capability, or NULL.
capability_t sys_vm_allocate(
    capability_compartment_t  comp,
    capability_quota_vm_t     mem_quota,
    size_t                    size,
    uint32_t                  flags
);

// Frees `mem_capability` and credits the bytes back to `mem_quota`. The range
// is quarantined, not unmapped: it stays reachable until the revocation sweep.
void sys_vm_deallocate(
    capability_compartment_t comp,
    capability_quota_vm_t    mem_quota,
    capability_t             mem_capability
);

// Creates a copy-on-write alias of `src_memory`. Full `len` is debited up front.
// `src_memory` must be global: a local (thread-stack-derived) source is refused.
capability_t sys_cow(
    capability_compartment_t comp,
    capability_quota_vm_t    mem_quota,
    capability_data_t        src_memory,
    size_t                   len
);

// Physical address of the base of an allocation `comp` owns, if the whole
// of `mem_capability`'s bounds is one physically contiguous run; 0 otherwise.
// This is the one fact about its memory a compartment cannot learn itself,
// and the one a device driver needs before it can point a DMA engine at a
// buffer. Reveals nothing about memory the caller does not already hold.
uint64_t sys_vm_phys(
    capability_compartment_t comp,
    capability_t             mem_capability
);

// Mints a revocation authority (`OType::Revoker`) covering `mem_cap`'s bounds
// `[base, top)` with `Permit_Load | Permit_Store`. Requires `mem_cap` to carry
// `Permit_Load | Permit_Store` and lie wholly within a virtual memory range
// owned by `comp`, so a compartment cannot obtain revocation authority over
// borrowed memory. Uses 0 bytes of kernel memory.
capability_revoker_t sys_revoke_create(
    capability_compartment_t comp,
    capability_t             mem_cap
);

// Derives a child revocation authority (`OType::Revoker`) bounded to `sub_cap`
// with permissions restricted to `permissions & (Permit_Load | Permit_Store)`.
// Requires `Permit_Store` on `parent_revoker` and `sub_cap` to lie wholly
// within `parent_revoker`'s range. Uses 0 bytes of kernel memory.
capability_revoker_t sys_revoke_derive(
    capability_revoker_t parent_revoker,
    capability_t         sub_cap,
    uint32_t             permissions
);

// Queues `mem_cap`'s range for the next revocation sweep. Returns the target
// epoch, or 0 if the range was refused.
//
// The backlog is paid for: the range is recorded on a page funded by
// `mem_quota` (a `QuotaVm` handle with `Permit_Load`). One page holds a few
// hundred ranges; a new one is charged when the caller's current page is full,
// and every page is refunded once the sweep has run. A caller that registers
// faster than the kernel sweeps exhausts only its own quota.
uint64_t sys_revoke_register(
    capability_revoker_t  revoker_cap,
    capability_t          mem_cap,
    capability_quota_vm_t mem_quota
);

// The highest epoch whose sweep has finished.
uint64_t sys_revoke_query(void);

// --- 5.2 Virtual memory quotas ---------------------------------------------

// Boot-time root quota over all system memory.
capability_quota_vm_t sys_quota_vm_create_root(
    size_t total_system_bytes
);

// Derives an immutable child budget. Debits `amount_bytes` + QUOTA_NODE_COST
// from the parent. Requires Permit_Store.
capability_quota_vm_t sys_quota_vm_derive(
    capability_quota_vm_t parent_quota,
    size_t                amount_bytes,
    uint32_t              permissions
);

// Refunds the full limit to the parent. Requires Permit_Store, no children and
// no live allocations.
int sys_quota_vm_destroy(
    capability_quota_vm_t quota
);

// --- 5.3 Thread memory quotas ----------------------------------------------

capability_quota_thread_mem_t sys_quota_thread_mem_create_root(
    size_t total_bytes
);

capability_quota_thread_mem_t sys_quota_thread_mem_derive(
    capability_quota_thread_mem_t parent_quota,
    size_t                        amount_bytes,
    uint32_t                      permissions
);

int sys_quota_thread_mem_destroy(
    capability_quota_thread_mem_t quota
);

// --- 5.4 Compartments, entry points and types ------------------------------

// Creates a protection domain funded from `mem_quota` and seeds its capability
// table from `initial_capabilities`. The array's bounds set both the count and
// the table's size: up to 238 seeds fit the one-page minimum, a longer array
// (pad it with nulls to reserve room) buys a table of as many pages as it
// needs, up to `compartment::MAX_COMPARTMENT_PAGES`, from the same quota.
capability_compartment_t sys_compartment_create(
    capability_quota_vm_t mem_quota,
    capability_data_t     initial_capabilities
);

void sys_compartment_destroy(
    capability_compartment_t comp
);

// The switcher. `entry` is an `OType::EntryPoint` handle: a compartment entry
// point from `sys_sentry`, or one of the kernel's own system calls (every
// other slot `syscall::gate` fills). Pushes a return frame, narrows the
// caller's stack for the callee, enters it, and on return scrubs the stack
// the callee used and every volatile register. See section 4.1 and
// sentry.hpp.
//
// For a compartment entry the callee gets `arg` in `ca0` and nothing comes
// back by register: the result is 0. For a kernel entry the caller's
// `ca1..ca5` are the kernel's `ca0..ca4` and the kernel's return value comes
// back in `ca0` -- `syscall::call` below applies the right signature. If the
// call is refused (bad handle, caller's stack unusable or too small, kernel
// stack full) the result is the `Status`, and the callee was never entered.
uint64_t sys_compartment_invoke(
    capability_sentry_t entry,
    capability_t        arg
);

// Mints an entry point for `comp`: records `{code, comp}` in one of `comp`'s
// entry pages and returns a sealed pointer to that record. `code` must lie in
// memory owned by `comp`. A new entry page is billed to `comp`'s quota when
// the existing ones are full.
capability_sentry_t sys_sentry(
    capability_compartment_t comp,
    capability_exec_t        code
);

// Mints a type key naming `record`. The record's ADDRESS is the type identity;
// its contents are never read.
capability_type_t sys_type_mint(
    capability_t record
);

// Re-issues `key` with a subset of its permissions. Permit_Store authorizes
// sealing, Permit_Load authorizes unsealing.
capability_type_t sys_type_derive(
    capability_type_t key,
    uint32_t          permissions
);

// Seals `obj` under `key`, storing a tagged copy of `key` in the object's
// 16-byte header. Requires Permit_Store on the key.
capability_sealed_t sys_seal(
    capability_type_t key,
    capability_data_t obj
);

// Opens `handle` if its header holds a tagged OTYPE_TYPE_KEY capability whose
// address equals `key`'s. Requires Permit_Load on the key.
capability_data_t sys_unseal(
    capability_type_t   key,
    capability_sealed_t handle
);

// --- 5.5 Threads -----------------------------------------------------------

capability_thread_t sys_thread_create(
    capability_quota_thread_mem_t thread_mem_quota,
    size_t                        stack_size,
    capability_sentry_t           entry,
    capability_t                  initial_arg
);

void sys_thread_exit(
    int status
);

void sys_thread_kill(
    capability_thread_t thread
);

// Runs `thread` (requires Permit_Load) and parks the caller until something
// switches back to it. Returns 0 (`Status::Ok`) when the caller is resumed, or
// the `Status` of a refused switch (not a live, halted thread handle).
uint64_t sys_thread_switch(
    capability_thread_t thread
);

// The kernel's id of the thread behind `thread` -- any live `OType::Thread`
// handle, operational or administrative -- or 0 if `thread` is not one. Ids
// start at 1 and are never reused, so one is a safe name for a thread in a
// user-level table; the scheduler keys its records by it (there is no second
// "scheduler tid").
uint64_t sys_thread_tid(
    capability_thread_t thread
);

// --- 5.6 Traps and interrupts ----------------------------------------------

void sys_trap_bind(
    capability_compartment_t comp,
    capability_t             auth_cap,
    capability_sentry_t      target
);

void sys_trap_unbind(
    capability_compartment_t comp,
    capability_t             auth_cap
);

} // extern "C"

namespace signetos::syscall {

// Every syscall in section 5, in declaration order. This single list drives
// the `Id` enum, the kernel entry record table in syscall.cpp, and (by
// position) the `RW_SLOT_SYSCALL_BASE + i` seed slots in init.hpp.
#define SIGNETOS_SYSCALLS(X) \
  X(vm_allocate)                  \
  X(vm_deallocate)                \
  X(cow)                          \
  X(vm_phys)                      \
  X(revoke_create)                \
  X(revoke_derive)                \
  X(revoke_register)              \
  X(revoke_query)                 \
  X(quota_vm_create_root)         \
  X(quota_vm_derive)              \
  X(quota_vm_destroy)             \
  X(quota_thread_mem_create_root) \
  X(quota_thread_mem_derive)      \
  X(quota_thread_mem_destroy)     \
  X(compartment_create)           \
  X(compartment_destroy)          \
  X(compartment_invoke)           \
  X(sentry)                       \
  X(type_mint)                    \
  X(type_derive)                  \
  X(seal)                         \
  X(unseal)                       \
  X(thread_create)                \
  X(thread_exit)                  \
  X(thread_kill)                  \
  X(thread_switch)                \
  X(thread_tid)                   \
  X(trap_bind)                    \
  X(trap_unbind)

enum class Id : uint32_t {
#define SIGNETOS_SYSCALL_ID(n) n,
  SIGNETOS_SYSCALLS(SIGNETOS_SYSCALL_ID)
#undef SIGNETOS_SYSCALL_ID
  Count
};

constexpr size_t kSyscallCount = static_cast<size_t>(Id::Count);

// Stack a kernel entry runs on: exactly this many bytes of the caller's own
// stack, directly below its `csp`, scrubbed by the switcher on the way out. A
// caller with less than this free is refused with `Status::StackTooSmall`.
// `sys_thread_switch` is the exception: it needs no caller stack at all (its
// frame and its C++ live on the kernel stack), so its record says 0.
//
// Measured (pattern-fill the slice in `__signetos_switcher_prepare`, scan it in
// `__signetos_switcher_return`, test image + production demo, -O2): the deepest
// entry is `thread_create` at 672 bytes, then `sentry` 576, the two quota
// derives 544, `vm_allocate` 496, `compartment_create` 464; everything else is
// under 400 and `type_mint`/`unseal`/`thread_tid` touch none. 4096 is six times
// the worst case. Re-measure before adding a syscall with large locals.
constexpr uint64_t SYSCALL_STACK_BYTES = 4096;

// Builds the kernel's entry records from the running kernel PCC. Called once
// at boot, after `sentry::init`, before anything asks for a gate.
void init();

// What a compartment is given to make system call `id`:
//
//   - `Id::compartment_invoke`: the switcher itself, a `CT = 1` hardware
//     sentry bounded to the kernel image with `CodeRx | AccessSystemRegs`.
//     It is the only `CT = 1` sentry a compartment ever holds.
//   - every other id: an `OType::EntryPoint` handle (`CT = 12`, Permit_Load
//     only) over a kernel-owned `sentry::EntryRecord` marked
//     `ENTRY_FLAG_TRUSTED`. It cannot be jumped to; it is passed to the
//     switcher in `ca0`, exactly like a compartment entry point.
Capability gate(Id id);

// Calls kernel entry `entry` through the switcher `invoke_gate` with the
// signature of `Fn`, a `sys_*` function pointer type:
//
//   using FnAlloc = decltype(&sys_vm_allocate);
//   Capability mem = syscall::call<FnAlloc>(invoke_gate, alloc_entry,
//                                           comp, quota, size, flags);
//
// This is only the register convention written down once: the switcher takes
// the entry in `ca0` and the kernel's `ca0..ca3` in `ca1..ca4`, and returns
// the kernel's `ca0`. A refused call (see `sys_compartment_invoke`: wrong
// handle, unusable or too small a stack, kernel stack full) returns the
// `Status` instead, in the same register; all of those are the caller's own
// doing, a correct caller never sees one.
template <typename Fn>
struct Via;

template <typename R, typename... A>
struct Via<R (*)(A...)> {
  static_assert(sizeof...(A) <= 4,
                "a kernel entry takes at most four arguments (ca1..ca4)");
  using Switcher = R (*)(Capability entry, A...);
  __attribute__((always_inline)) static R call(Capability invoke_gate,
                                               Capability entry, A... args) {
    return reinterpret_cast<Switcher>(invoke_gate)(entry, args...);
  }
};

template <typename Fn, typename... A>
__attribute__((always_inline)) inline auto call(Capability invoke_gate,
                                                Capability entry, A... args) {
  return Via<Fn>::call(invoke_gate, entry, args...);
}

} // namespace signetos::syscall
