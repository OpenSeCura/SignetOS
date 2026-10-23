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
// syscall.hpp - SignetOS microkernel system call interface
//
// The complete kernel ABI: every call is in SIGNETOS_SYSCALLS below. Nothing
// outside this header is reachable by a compartment.
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

// --- Handle types ----------------------------------------------------------

using capability_t             = signetos::Capability;  // any memory capability
using capability_data_t        = signetos::Capability;  // non-executable memory
using capability_exec_t        = signetos::Capability;  // executable, unsealed

using capability_quota_vm_t         = signetos::Capability;  // OTYPE_QUOTA_VM
using capability_quota_thread_mem_t = signetos::Capability;  // OTYPE_QUOTA_THREAD_MEM
using capability_compartment_t      = signetos::Capability;  // OTYPE_COMPARTMENT
using capability_thread_t           = signetos::Capability;  // OTYPE_THREAD
using Sentry                       = signetos::Sentry;
using capability_sentry_t           = Sentry;                // OTYPE_SENTRY

// --- sys_vm_allocate flags -------------------------------------------------

// Every allocation comes back zeroed, at addresses never handed out before.
//
// FLAG_DMA: memory a device will be pointed at. The allocation is one
// physically contiguous run, and its first 8 bytes hold the physical address
// of its base (everything else is zero). A device without an IOMMU needs that
// address, and it is the one fact about its memory a compartment cannot learn
// itself; it reveals nothing about anyone else's memory, and a compartment
// that can program a DMA engine can reach all of RAM anyway. Refused (null)
// if the run is not contiguous. Nothing moves memory today; anything that
// does later must leave these allocations where they are.
constexpr uint32_t FLAG_DMA = (1u << 0);

// FLAG_REVOCABLE: memory its owner will hand out in pieces and take back
// with `sys_revoke`, such as a heap arena. Only parts of these can be
// revoked. The kernel keeps one bit per 16 bytes of it, the revocation marks,
// and charges them to the same quota: one page per 512KB, rounded up, so 4KB
// for anything up to 512KB.
constexpr uint32_t FLAG_REVOCABLE = (1u << 1);

extern "C" {

// --- Virtual memory --------------------------------------------------------

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

// Marks `mem_cap`'s range for the next revocation sweep, which revokes every
// capability whose BASE lies in it (revoke.hpp, THE BASE RULE): the way an
// owner takes back part of an allocation it keeps, such as an object its
// heap is freeing. The range must lie inside one of `comp`'s own
// FLAG_REVOCABLE allocations, must not include that allocation's first byte,
// which is where the owner's own capability to the allocation is based, and
// must start and end on a multiple of 16 bytes. Returns the current epoch, N:
// the range may be reused once `sys_revoke_query()` reaches N. Returns 0 if
// the range was refused.
uint64_t sys_revoke(
    capability_compartment_t comp,
    capability_t             mem_cap
);

// How many sweeps have completed (the completed epoch), having swept first if
// the interval allows (revoke.hpp, WHEN A SWEEP RUNS).
uint64_t sys_revoke_query(void);

// --- Virtual memory quotas -------------------------------------------------

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

// Closes the quota: nothing more can be charged or derived through it, and its
// unused budget goes back to the parent now. What it funded carries on; the
// rest of the budget follows once all of that is freed (quota.hpp, DESTROY
// CLOSES, IT DOES NOT KILL). Requires Permit_Store.
int sys_quota_vm_destroy(
    capability_quota_vm_t quota
);

// --- Thread memory quotas --------------------------------------------------

capability_quota_thread_mem_t sys_quota_thread_mem_create_root(
    size_t total_bytes
);

capability_quota_thread_mem_t sys_quota_thread_mem_derive(
    capability_quota_thread_mem_t parent_quota,
    size_t                        amount_bytes,
    uint32_t                      permissions
);

// As sys_quota_vm_destroy. Threads the quota funded keep running.
int sys_quota_thread_mem_destroy(
    capability_quota_thread_mem_t quota
);

// --- Compartments and entry points -----------------------------------------

// Creates a protection domain funded from `mem_quota` and seeds its capability
// table from `initial_capabilities`: slot 0 is the new compartment's own
// handle, and seed i lands in slot 1 + i, copied as it is (what each seed is
// is between the creator and the image; `mem_quota` itself is not put in the
// table unless it is passed as a seed). The array's bounds set both the count
// and the table's size: up to 239 seeds fit the one-page minimum, a longer
// array (pad it with nulls to reserve room) buys a table of as many pages as
// it needs, up to `compartment::MAX_COMPARTMENT_PAGES`, from the same quota.
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
// the callee used and every volatile register. See sentry.hpp.
//
// The caller's `ca1..ca5` become the callee's `ca0..ca4`, and the callee's
// return value comes back in `ca0` (checked against the outbound capability
// policy). If the call is refused (bad handle, caller's stack unusable or too
// small, kernel stack full) the result is the `Status`, and the callee was
// never entered.
uint64_t sys_compartment_invoke(
    Sentry       entry_point,
    capability_t arg
);

// Mints an entry point for `comp`: records `{code, comp}` in one of `comp`'s
// entry pages and returns a sealed pointer to that record. `code` must lie in
// memory owned by `comp`. A new entry page is billed to `comp`'s quota when
// the existing ones are full.
Sentry sys_sentry(
    capability_compartment_t comp,
    capability_exec_t        code
);

// Makes `code` `comp`'s fault handler (fault.hpp), replacing any installed
// before. `code` must lie in memory owned by `comp`, as for `sys_sentry`. The
// handler is kept in `comp`'s descriptor and never handed out: only the trap
// dispatcher enters it. Returns a `Status` (0 = installed).
uint64_t sys_fault_install(
    capability_compartment_t comp,
    capability_exec_t        code
);

// Compartment-minted sealing types (type keys and sealed objects,
// CORE_DESIGN.md §2.3) are not kernel calls. The user-space `sealer` service
// (external/services/sealer.cpp) provides them as the `seal.*` entry points,
// holding the `OType::TypeKey` and `OType::SealedObject` authorities that
// `init` delegates to it; the mechanism itself is the library user/vseal.hpp.

// --- Threads ---------------------------------------------------------------

capability_thread_t sys_thread_create(
    capability_quota_thread_mem_t thread_mem_quota,
    size_t                        stack_size,
    Sentry                        entry_point,
    capability_t                  initial_arg
);

void sys_thread_exit(
    int status
);

// Ends `thread` (requires Permit_Store). Never run: torn down now. Has run:
// marked, and it ends when the kernel is next about to resume its own code
// (unwind.hpp, KILLED THREADS); until then it must be kept runnable, which is
// the scheduler's job (`sched.thread_kill`). Returns a `Status`: Ok,
// InvalidCapability (not a live thread, or already ending) or
// InsufficientPermission.
uint64_t sys_thread_kill(
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

// --- Traps and interrupts --------------------------------------------------

// Installs `handler`, a compartment entry point, as the handler of `irq`:
// IRQ_M_TIMER (the scheduler's tick) or IRQ_M_EXT (the trap manager). Once
// each, for good (irq.hpp, INTERRUPT HANDLERS). `init` calls it at boot and
// hands the gate to nobody. Returns a `Status`: Ok, InvalidAuthority (another
// `irq`), InvalidSentry, or Busy (already installed).
uint64_t sys_trap_install(
    uint64_t irq,
    Sentry   handler
);

// --- Paging (vm.hpp, PAGING) -------------------------------------------------

// Turns paging on, once, for `slots` pages of swap. `init` calls it after it
// has started what paging depends on. A `Status` (vm::setup_paging).
uint64_t sys_page_setup(
    size_t slots
);

// The pager's (`blk`'s): the next job, vm::PAGE_NONE or a read or write of a
// slot (vm::page_next), with `buf` its 4 KiB page for the transfer; and that
// the job is done (vm::page_done).
uint64_t sys_page_next(
    capability_data_t buf
);
void sys_page_done(
    capability_data_t buf
);

// For the shell's `pagetest`: vm::page_test.
uint64_t sys_page_test(
    uint64_t     op,
    capability_t cap
);

} // extern "C"

namespace signetos::syscall {

// Every syscall in declaration order. This single list drives
// the `Id` enum, the kernel entry record table in syscall.cpp, and (by
// position) the `RW_SLOT_SYSCALL_BASE + i` seed slots in init.hpp.
#define SIGNETOS_SYSCALLS(X) \
  X(vm_allocate)                  \
  X(vm_deallocate)                \
  X(cow)                          \
  X(revoke)                       \
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
  X(fault_install)                \
  X(thread_create)                \
  X(thread_exit)                  \
  X(thread_kill)                  \
  X(thread_switch)                \
  X(thread_tid)                   \
  X(trap_install)                 \
  X(page_setup)                   \
  X(page_next)                    \
  X(page_done)                    \
  X(page_test)

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
// under 400 and `thread_tid` touches none. 4096 is six times the worst case.
// Re-measure before adding a syscall with large locals.
constexpr uint64_t SYSCALL_STACK_BYTES = 4096;

// Builds the kernel's entry records from the running kernel PCC. Called once
// at boot, after `sentry::init`, before anything asks for a gate.
void init();

// What a compartment is given to make system call `id`:
//
//   - `Id::compartment_invoke`: the switcher itself, a `CT = 1` hardware
//     sentry bounded to the kernel image with `CodeRx | AccessSystemRegs`.
//     It is the only `CT = 1` sentry a compartment ever holds.
//   - every other id: an `OType::EntryPoint` handle (`CT = 18`, Permit_Load
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
// the entry in `ca0` and the callee's `ca0..ca4` in `ca1..ca5`, and returns
// the callee's `ca0`. A refused call (see `sys_compartment_invoke`: wrong
// handle, unusable or too small a stack, kernel stack full) returns the
// `Status` instead, in the same register; all of those are the caller's own
// doing, a correct caller never sees one.
template <typename Fn>
struct Via;

template <typename R, typename... A>
struct Via<R (*)(A...)> {
  static_assert(sizeof...(A) <= 5,
                "an entry takes at most five arguments (ca1..ca5)");
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
