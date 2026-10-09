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
// 1. `QuotaThreadMem` (OType::QuotaThreadMem, CT = 3):
//    Hierarchical, page-backed quota governing thread execution memory
//    (user stacks, `ThreadState`, and kernel return stacks). A second
//    `quota::Tree` instance, identical to `QuotaVm` except for its OType.
//      - Permit_Load  -> operational authority (fund threads via create)
//      - Permit_Store -> administrative authority (derive / destroy quotas)
//
// 2. `ThreadState` (OType::Thread, CT = 8):
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
#include <signetos/platform.hpp>
#include <signetos/quota.hpp>
#include <signetos/sentry.hpp>
#include <signetos/types.hpp>
#include <signetos/vm.hpp>

namespace signetos::thread {

using quota::QUOTA_NODE_COST;
using quota::QUOTA_NODE_PAGES;

// Tunable parameter controlling the per-thread kernel allocation size (in 4 KiB
// pages). `ThreadState` (464 bytes) occupies the front of this allocation and
// the remaining space (`THREAD_STATE_COST - sizeof(ThreadState)`) is the
// thread's kernel stack. It holds frames only -- the `SwitchFrame`, one
// `ReturnFrame` per call in progress through the switcher, the `TrapFrame`s
// of traps taken in the thread -- plus the switcher's and trap dispatcher's
// own C++ helpers directly below the frame they manage. System call bodies do
// not run here: they run on the caller's own stack, narrowed, like any other
// callee (see sentry.hpp).
//
// The size sets how deep a thread's compartment calls can nest, and how deep
// a handler chain can run on top of them (asm_macros.h, KERNEL-STACK ROOM):
// one page allowed four nested calls with interrupts enabled, and a two-call
// handler chain (an interrupt -> the driver's IRQ entry -> `sched.wake`) only
// over a thread at depth 3 or less, so a program launched by the shell on
// the shell's thread (shell -> program -> fs -> blk -> sched.block, depth 4)
// lost its disk completion. Two pages allow fourteen nested calls and that
// chain over a thread at depth 13. The cost is billed to the thread's
// funding quota like the stack is.
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
// kernel is about to resume its own code (unwind.hpp, KILLED THREADS).
constexpr uint32_t FLAG_KILL_PENDING = (1u << 5);

using Status = signetos::Status;
using signetos::status_name;

// The thread-memory quota is a `quota::Tree` (OType::QuotaThreadMem) with the
// same node layout as the VM quota.
using QuotaThreadMem = quota::QuotaNode;

// Saved register frame pushed onto a thread's kernel stack (`kernel_sp`) across
// `dispatch()` context switches, and pre-populated at the top of the kernel
// stack by `create()` so a newly created thread starts through the same path.
struct alignas(16) SwitchFrame {
  Capability ra;
  Capability sp;
  Capability gp;
  Capability active_kernel_sp;  // 48: FRAME LINK (asm_macros.h)
  Capability t[7];
  Capability s[12];
  Capability a[8];
  Capability tp;                // 496
};

static_assert(sizeof(SwitchFrame) == 32 * sizeof(Capability),
              "SwitchFrame must be 32 capabilities (512 bytes)");

// Occupies the front of the thread's state pages; the remainder,
// `[sizeof(ThreadState), THREAD_STATE_COST)`, is the thread's kernel return
// stack.
struct alignas(16) ThreadState {
  Capability self_page;      // writable kernel capability to this thread's page
  Capability funding_quota;  // sealed OTYPE_QUOTA_THREAD_MEM that paid
  Capability stack_alloc;    // unsealed DataRw allocation for user stack
  Capability entry_sentry;   // validated OType::EntryPoint (CT = 12)
  Capability initial_arg;    // initial value for ca0
  Capability user_sp;        // top of user stack ([base, base + stack_bytes))
  Capability kernel_sp;      // saved kernel stack pointer (SwitchFrame* when halted)

  uint64_t tid;
  uint64_t total_billed;     // THREAD_STATE_COST + stack_bytes
  uint32_t flags;
  int32_t exit_status;
};

static_assert(sizeof(ThreadState) + sizeof(SwitchFrame) <= 1024,
              "ThreadState must leave room in the allocation for the kernel "
              "return stack");

// Kernel-wide initialisation, once, before any hart runs threads.
void init();

// Per-hart initialisation: installs this hart's state block (which thread it
// is running, where its host frame is), found through the hart number kept
// in `utidc`. Every hart calls it once, on itself, before it runs any thread.
// Harts are numbered from 0 and discovered from `/cpus/cpu@*` in the DTB.
constexpr size_t MAX_HARTS = platform::MAX_HARTS;
void init_hart(uint64_t hartid);

// Brings up every secondary hart present in the DTB (`platform::hart_present`),
// carving each hart's 64 KiB host stack (`csp`) and 16 KiB kernel entry stack
// (`sscratchc`) from the identity-mapped kernel region above `_kernel_end` and
// waiting until each hart has completed `init_hart` and `trap::init_hart`.
void bring_up_secondary_harts(Capability root_data_cap, uint64_t boot_hart);

// Number of harts that have completed `init_hart`.
size_t online_harts();

// The number of the hart this is running on (the one `init_hart` was given).
uint64_t this_hart();

// --- Thread memory quota operations ----------------------------------------

// Boot-only root thread memory quota. Its whole budget is charged to `vm_quota`
// up front, so thread memory and VM allocations together can never promise
// more memory than physically exists. Null if a root already exists or
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

// Dispatches execution to `thread_handle` (requires Permit_Load), saving the
// current thread's full register state onto its kernel stack and loading the
// target thread's state from its kernel stack. This is the `sys_thread_switch`
// kernel entry itself: a thread reaches it through the switcher, the host
// (`init::launch`, the test suites) calls it directly. Returns `Status::Ok`
// when this context is next resumed, or the reason the switch was refused.
Status dispatch(Capability thread_handle) __asm__("sys_thread_switch");

// Terminates the currently running thread with `exit_status`, reclaiming its
// stack and state page back to its `funding_quota` and returning control to the
// caller of `dispatch()`.
void exit(int exit_status);

// Ends a thread (requires Permit_Store on `thread_handle`). A thread that has
// never run is torn down here, its stack and state page refunded to its
// `funding_quota`. A thread that has run is only marked (FLAG_KILL_PENDING):
// it keeps running until the kernel is about to resume its own code, and ends
// there (unwind.hpp, KILLED THREADS). Keeping it runnable until then is the
// scheduler's job (`sched.thread_kill`). InvalidCapability if it is not a
// live thread or is already ending.
Status kill(Capability thread_handle);

// True if the thread running on this hart has been killed.
bool current_kill_pending();

// The kernel's id of the thread behind `thread_handle` (any live handle:
// nothing beyond what every handle carries is required), or 0 if it is not a
// live `OType::Thread`. Ids start at 1 and are never reused.
uint64_t tid_of(Capability thread_handle);

// The id of the thread running on this hart, or 0 in host context.
uint64_t current_tid();

// Reads the current hart's active kernel stack capability from `sscratchc`
// (the boot kernel stack when executing in host context).
inline Capability current_kernel_sp() {
  Capability ksp;
  __asm__ volatile("csrr %0, sscratchc" : "=C"(ksp));
  return ksp;
}

// Updates the current hart's active kernel stack capability in `sscratchc`.
inline void set_kernel_sp(Capability ksp) {
  __asm__ volatile("csrw sscratchc, %0" : : "C"(ksp));
}

// Bytes free on a kernel stack below `ksp` -- `sscratchc` itself or a frame
// carved from it, both carry the stack's bounds. The switcher and the trap
// dispatcher compare this against the budget in asm_macros.h.
inline uint64_t kernel_stack_free(Capability ksp) {
  return capability_get_address(ksp) - capability_get_base(ksp);
}

size_t live_threads();

}  // namespace signetos::thread
