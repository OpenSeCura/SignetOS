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
// thread.hpp - SignetOS Thread Memory Quotas and Thread Execution State
//
// TWO SEALED KERNEL OBJECTS
// -------------------------
// 1. `QuotaThreadMem` (OType::QuotaThreadMem, CT = 9):
//    Hierarchical, page-backed quota governing thread execution memory
//    (user stacks, `ThreadState`, and kernel return stacks). A second
//    `quota::Tree` instance, identical to `QuotaVm` except for its OType.
//      - Permit_Load  -> operational authority (fund threads via create)
//      - Permit_Store -> administrative authority (derive / destroy quotas)
//
// 2. `ThreadState` (OType::Thread, CT = 14):
//    Occupies `THREAD_STATE_PAGES` pages (`THREAD_STATE_COST = 8192`): the
//    `ThreadState` struct at the front (`[0, sizeof(ThreadState))`), and the
//    thread's kernel-private return stack behind it (`[sizeof(ThreadState),
//    THREAD_STATE_COST)`). The handle
//    returned by `sys_thread_create` is bounded to `sizeof(ThreadState)` and
//    sealed with `OType::Thread`.
//      - Permit_Load  -> operational authority (dispatch via sys_thread_switch)
//      - Permit_Store -> administrative authority (terminate via sys_thread_kill)
//

#include <stddef.h>
#include <stdint.h>
#include <signetos/hw/platform.hpp>
#include <signetos/quota.hpp>
#include <signetos/sentry.hpp>
#include <signetos/trap.hpp>
#include <signetos/types.hpp>
#include <signetos/vm.hpp>

namespace signetos::thread {

using quota::QUOTA_NODE_COST;
using quota::QUOTA_NODE_PAGES;

// Tunable parameter controlling the per-thread kernel allocation size (in 4 KiB
// pages). `ThreadState` (144 bytes) occupies the front of this allocation and
// the remaining space (`THREAD_STATE_COST - sizeof(ThreadState)`) is the
// thread's kernel stack. It holds frames only -- one `ReturnFrame` per call
// in progress through the switcher, and `TrapFrame`s: one for each trap in
// progress, and, while the thread is not running, the one it is parked in
// (PARKED THREADS) -- plus the switcher's and trap dispatcher's own C++
// helpers directly below the frame they manage. System call bodies do not
// run here: they run on the caller's own stack, narrowed, like any other
// callee (see sentry.hpp).
//
// The size sets how deep a thread's compartment calls can nest
// (asm_macros.h, KERNEL-STACK ROOM): two pages allow sixteen. The cost is
// billed to the thread's funding quota like the stack is.
constexpr size_t THREAD_STATE_PAGES = 2;
constexpr uint64_t THREAD_STATE_COST = THREAD_STATE_PAGES * vm::PAGE_SIZE;

// `ThreadState::flags`.
constexpr uint32_t FLAG_LIVE = (1u << 1);
constexpr uint32_t FLAG_RUNNING = (1u << 2);
constexpr uint32_t FLAG_EXITED = (1u << 3);
// Set by the first dispatch and never cleared: the thread has run, so it may
// be inside a compartment call, and `kill` only marks it.
constexpr uint32_t FLAG_STARTED = (1u << 4);
// Set by `kill` on a thread that has run. The thread ends the next time the
// kernel is about to resume its own code, inside no call (unwind.hpp,
// KILLED THREADS).
constexpr uint32_t FLAG_KILL_PENDING = (1u << 5);

using Status = signetos::Status;
using signetos::status_name;

// The thread-memory quota is a `quota::Tree` (OType::QuotaThreadMem) with the
// same node layout as the VM quota.
using QuotaThreadMem = quota::QuotaNode;

// PARKED THREADS
//
// A thread that is not running is parked in a `TrapFrame` on top of its
// kernel stack, whatever stopped it: an interrupt (the frame the trap vector
// pushed), `sys_thread_switch` or `sys_trap_wait` (which push one that
// resumes just after the call), or nothing yet (`create` builds one that
// starts at `__thread_start`).
// So there is one way to resume a thread: the trap return path
// (`unwind::resume`), which is also where a killed thread ends and where the
// frames of destroyed compartments are skipped.

// Occupies the front of the thread's state pages; the remainder,
// `[sizeof(ThreadState), THREAD_STATE_COST)`, is the thread's kernel return
// stack.
struct alignas(16) ThreadState {
  Capability self_page;      // writable kernel capability to this thread's page
  Capability funding_quota;  // sealed OTYPE_QUOTA_THREAD_MEM that paid
  Capability stack_alloc;    // unsealed DataRw allocation for user stack
  Capability entry_sentry;   // validated OType::EntryPoint (CT = 18)
  Capability initial_arg;    // initial value for ca0
  Capability user_sp;        // the entry's slice, at the top of the stack
  Capability kernel_sp;      // the TrapFrame it is parked in (PARKED THREADS)

  uint64_t tid;
  uint64_t total_billed;     // THREAD_STATE_COST + stack_bytes
  uint32_t flags;
  int32_t exit_status;
};

static_assert(sizeof(ThreadState) == 144,
              "ThreadState is 144 bytes (asm_macros.h, KERNEL-STACK ROOM)");

static_assert(sizeof(ThreadState) + sizeof(trap::TrapFrame) <= 1024,
              "ThreadState must leave room in the allocation for the kernel "
              "return stack");

// Kernel-wide initialisation, once, before any hart runs threads.
void init();

// Per-hart initialisation: installs this hart's state block (which thread it
// is running, where its host frame is), found through the hart number kept
// in `utidc`, which also holds the id of the thread the hart is running
// (platform.hpp, UTIDC_*). Every hart calls it once, on itself, before it
// runs any thread.
// Harts are numbered from 0 and discovered from `/cpus/cpu@*` in the DTB.
constexpr size_t MAX_HARTS = platform::MAX_HARTS;
void init_hart(uint64_t hartid);

// The number of the hart this is running on (the one `init_hart` was given).
uint64_t this_hart();

// --- Thread memory quota operations ----------------------------------------

// Boot-only root thread memory quota. Its whole budget is charged to `vm_quota`
// up front, so thread memory and VM allocations together never hand out more
// address space than the VM root has. Null if a root already exists or
// `vm_quota` cannot cover `total_bytes`.
Capability create_root_quota(Capability vm_quota, uint64_t total_bytes);

Capability derive_quota(Capability parent_handle, uint64_t amount_bytes,
                        uint64_t perms_mask, Status* out_status = nullptr);

Status destroy_quota(Capability quota_handle);

bool query_quota(Capability quota_handle, QuotaThreadMem* out_copy);

// --- Thread lifecycle operations -------------------------------------------

Capability create(Capability thread_mem_quota, size_t stack_size,
                  Capability entry_sentry, Capability initial_arg,
                  Status* out_status = nullptr);

// Dispatches execution to `thread_handle` (requires Permit_Load): parks the
// caller in a `TrapFrame` on its own kernel stack (PARKED THREADS) and
// resumes the target from the one it is parked in. This is the
// `sys_thread_switch` kernel entry itself: a thread reaches it through the
// switcher, the host (`init::launch`) calls it directly. Returns
// `Status::Ok` when this context is next resumed, or the reason the switch
// was refused. Refused while an interrupt is being handled on this hart:
// the handler leaves through `sys_trap_wait`.
Status dispatch(Capability thread_handle) __asm__("sys_thread_switch");

// Terminates the currently running thread with `exit_status`, reclaiming its
// stack and state page back to its `funding_quota` and returning control to the
// caller of `dispatch()` -- or, if it is the interrupt handler, to the thread
// it interrupted.
void exit(int exit_status);

// Ends a thread (requires Permit_Store on `thread_handle`). A thread that has
// never run is torn down here, its stack and state page refunded to its
// `funding_quota`. A thread that has run is only marked (FLAG_KILL_PENDING):
// it keeps running until the kernel is about to resume its own code, and ends
// there (unwind.hpp, KILLED THREADS). Keeping it runnable until then is the
// scheduler's job (`sched.thread_kill`). InvalidCapability if it is not a
// live thread or is already ending.
Status kill(Capability thread_handle);

// THE INTERRUPT HANDLER
//
// Each hart has one interrupt handler thread: an ordinary thread, created on
// the scheduler's interrupt entry, that this hart holds (FLAG_RUNNING) from
// `install_handler` on, so nothing else can switch to it. It waits in
// `sys_trap_wait`. An interrupt parks the thread it interrupts in the
// `TrapFrame` the trap vector pushed and resumes the handler from where it
// waits, masked, with the interrupt written to its `irq::Event`. The
// handler then calls `sys_trap_wait` again, naming the thread to run next.
// The first interrupt only starts the handler, at its entry point, and is
// not reported: it is the next tick, or a level that is still pending, or a
// page fault that is taken again.
//
// The interrupted thread stays this hart's until the handler has chosen, so
// it is released only once this hart is off its kernel stack.

// Makes `thread_handle` (Permit_Load and Permit_Store, never run) this
// hart's interrupt handler, for good. InvalidCapability if it is not such a
// thread, Busy if this hart has one.
Status install_handler(Capability thread_handle);

// For the trap dispatcher, with the `TrapFrame` the trap vector has just
// pushed: parks the running thread in it and resumes this hart's handler
// with `(cause, the parked thread's id, aux)`. Returns false, with nothing
// changed, if there is no handler waiting or no thread to park; otherwise
// does not return.
bool wake_handler(trap::TrapFrame* frame, uint64_t cause, uint64_t aux);

// True if the thread running on this hart has been killed.
bool current_kill_pending();

// The kernel's id of the thread behind `thread_handle` (any live handle:
// nothing beyond what every handle carries is required), or 0 if it is not a
// live `OType::Thread`. Ids start at 1 and are never reused.
uint64_t tid_of(Capability thread_handle);

// The id of the thread running on this hart, or 0 in host context.
uint64_t current_tid();

// The thread running on this hart's entry point (`OType::EntryPoint`), its
// whole stack, and the slice its entry was given. Null in host context.
Capability current_entry_sentry();
Capability current_user_stack();
Capability current_initial_sp();

// Reads the current hart's active kernel stack capability from `mscratchc`
// (the boot kernel stack when executing in host context).
inline Capability current_kernel_sp() {
  Capability ksp;
  __asm__ volatile("csrr %0, mscratchc" : "=C"(ksp));
  return ksp;
}

// Updates the current hart's active kernel stack capability in `mscratchc`.
inline void set_kernel_sp(Capability ksp) {
  __asm__ volatile("csrw mscratchc, %0" : : "C"(ksp));
}

// Bytes free on a kernel stack below `ksp` -- `mscratchc` itself or a frame
// carved from it, both carry the stack's bounds. The switcher and the trap
// dispatcher compare this against the budget in asm_macros.h.
inline uint64_t kernel_stack_free(Capability ksp) {
  return capability_get_address(ksp) - capability_get_base(ksp);
}

size_t live_threads();

}  // namespace signetos::thread
