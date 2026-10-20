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
 * thread.cpp - SignetOS Thread Memory Quotas and Thread Execution State
 */

#include <signetos/debug/inspect.hpp>
#include <signetos/lock.hpp>
#include <signetos/quota.hpp>
#include <signetos/sealing.hpp>
#include <signetos/sentry.hpp>
#include <signetos/syscall.hpp>
#include <signetos/thread.hpp>
#include <signetos/trap.hpp>
#include <signetos/debug/report.hpp>
#include <signetos/vm.hpp>

// Thread context switching, restoration, teardown pivot, and startup trampoline
// are implemented in `kernel/switch.S`.
extern "C" void __thread_restore(signetos::Capability next_ksp);
extern "C" void __thread_exit_to_host(signetos::thread::ThreadState* t,
                                      signetos::Capability host_ksp);
extern "C" void __thread_start(void);
extern "C" signetos::Capability __thread_start_link(void);

namespace signetos::thread {
namespace {

// The thread-memory quota tree (OType::QuotaThreadMem). Same implementation
// as the VM tree; see quota.hpp.
quota::Tree s_quota_tree;

uint64_t s_next_tid = 0;
size_t s_live_threads = 0;

// Per-hart state. "Which thread is running" and "where is the host frame" are
// facts about a hart, not about the kernel, so each hart has its own block.
// A hart finds its block by its number, which the kernel keeps in `utidc`
// (CSR 0x480) as an untagged integer, together with the id of the thread the
// hart is running (platform.hpp, UTIDC_*). `utidc` is readable without ASR, so
// a compartment can learn both too (`trap_mgr` reads the hart number, a lock
// the thread id); nothing with authority goes in it. Writing it takes ASR,
// which compartment code (CodeRx) does not have, so no compartment can change
// the number this lookup uses, or pass itself off as another thread.
// (`stdc`, 0x163, would carry a capability and is
// S-mode only, but this QEMU traps on it.)
struct alignas(16) Cpu {
  ThreadState* current;       // thread this hart is running; null in host context
  Capability host_kernel_sp;  // this hart's host SwitchFrame while a thread runs
  uint64_t hart_id;
  uint64_t pad_;
};
Cpu s_cpus[MAX_HARTS];

Cpu* cpu() {
  Capability id;
  __asm__ volatile("csrr %0, 0x480" : "=C"(id));  // 0x480 = utidc
  return &s_cpus[capability_get_address(id) & platform::UTIDC_HART_MASK];
}

// Records in `utidc` which hart this is and which thread it is running (0 for
// none). An untagged value: numbers only, no authority.
void set_utidc(uint64_t hart, uint64_t tid) {
  const Capability id = reinterpret_cast<Capability>(
      static_cast<uintptr_t>(hart | (tid << platform::UTIDC_TID_SHIFT)));
  __asm__ volatile("csrw 0x480, %0" : : "C"(id));  // 0x480 = utidc
}

ThreadState* unseal_thread(Capability handle) {
  return sealing::open_live<ThreadState>(OType::Thread, handle, FLAG_LIVE);
}

void teardown_thread(ThreadState* t) {
  if (t == nullptr || (t->flags & FLAG_LIVE) == 0) {
    return;
  }

  Capability state_page = t->self_page;
  Capability stack_cap = t->stack_alloc;
  Capability quota_cap = t->funding_quota;

  // Clear liveness and scrub stored capabilities in the state page.
  t->flags = 0;
  t->self_page = nullptr;
  t->funding_quota = nullptr;
  t->stack_alloc = nullptr;
  t->entry_sentry = nullptr;
  t->initial_arg = nullptr;
  t->user_sp = nullptr;
  t->kernel_sp = nullptr;

  // The quota pays for both until the sweep has reclaimed them, and is then
  // refunded through quota.cpp rather than the node itself: it may have been
  // destroyed while this thread ran, and this may be what empties it.
  if (capability_is_valid(stack_cap)) {
    quota::owe(quota_cap, vm::free_pages(stack_cap));
  }
  if (capability_is_valid(state_page)) {
    quota::owe(quota_cap, vm::free_pages(state_page));
  }

  __atomic_fetch_sub(&s_live_threads, 1, __ATOMIC_RELAXED);
}

}  // namespace

void init() {
  quota::init(s_quota_tree, OType::QuotaThreadMem);
  s_next_tid = 0;
  s_live_threads = 0;
}

void init_hart(uint64_t hartid) {
  if (hartid >= MAX_HARTS || !platform::hart_present(hartid)) {
    debug::panic("thread: hart id not in DTB or beyond MAX_HARTS");
  }
  Cpu* c = &s_cpus[hartid];
  *c = Cpu{};
  c->hart_id = hartid;
  set_utidc(hartid, 0);
}

uint64_t this_hart() { return cpu()->hart_id; }

size_t live_threads() {
  return __atomic_load_n(&s_live_threads, __ATOMIC_RELAXED);
}

Capability create_root_quota(Capability vm_quota, uint64_t total_bytes) {
  if (s_quota_tree.root_taken) {
    return nullptr;
  }

  // Paid for out of the VM quota, so the bytes promised to threads are bytes
  // the VM tree can no longer promise to anyone else.
  if (quota::charge(vm_quota, total_bytes) != Status::Ok) {
    return nullptr;
  }

  Capability handle = quota::create_root(s_quota_tree, total_bytes);
  if (!capability_is_valid(handle)) {
    quota::refund(vm_quota, total_bytes);
    return nullptr;
  }
  return handle;
}

Capability derive_quota(Capability parent_handle, uint64_t amount_bytes,
                        uint64_t perms_mask, Status* out_status) {
  return quota::derive(s_quota_tree, parent_handle, amount_bytes, perms_mask,
                       out_status);
}

Status destroy_quota(Capability quota_handle) {
  return quota::destroy(s_quota_tree, quota_handle);
}

bool query_quota(Capability quota_handle, QuotaThreadMem* out_copy) {
  return out_copy != nullptr &&
         quota::query(s_quota_tree, quota_handle, out_copy);
}

Capability create(Capability thread_mem_quota, size_t stack_size,
                  Capability entry_sentry, Capability initial_arg,
                  Status* out_status) {
  if (stack_size == 0) {
    return fail_with(out_status, Status::BadStackSize);
  }

  // Validate that entry_sentry is a genuine OType::EntryPoint (CT = 18) with
  // Permit_Load, and fetch the owning compartment's table for `cgp`. A kernel
  // entry is not a thread entry: it has no table and is only ever reached
  // through the switcher.
  sentry::Entry entry{};
  if (sentry::resolve(entry_sentry, &entry) != sentry::Status::Ok ||
      (entry.flags & sentry::ENTRY_FLAG_TRUSTED) != 0) {
    return fail_with(out_status, Status::InvalidCapability);
  }
  const Capability hw_sentry = entry.sentry;
  const Capability entry_table = entry.table;

  // `initial_arg` is remembered by the kernel and handed to a different
  // thread: a local capability (one derived from the creator's own stack)
  // must not travel that way, that is what local means.
  if (capability_is_valid(initial_arg) &&
      (capability_get_perms(initial_arg) & perms::Global) == 0) {
    return fail_with(out_status, Status::InvalidCapability);
  }
  // Nor may code: it never crosses a compartment boundary (DESIGN.md §2.5).
  if (inspect::is_user_code(initial_arg)) {
    return fail_with(out_status, Status::InvalidCapability);
  }

  const size_t stack_pages = (stack_size + vm::PAGE_SIZE - 1) / vm::PAGE_SIZE;
  const uint64_t stack_bytes = stack_pages * vm::PAGE_SIZE;
  const uint64_t total_cost = THREAD_STATE_COST + stack_bytes;
  if (total_cost < stack_bytes) {
    return fail_with(out_status, Status::OutOfQuota);
  }

  // charge() is also the check on the handle: it must be a genuine, open
  // thread-memory quota carrying Permit_Load with room for the thread.
  const Status charged =
      quota::charge(s_quota_tree, thread_mem_quota, total_cost);
  if (charged != Status::Ok) {
    return fail_with(out_status, charged);
  }
  // Through the handle: the quota may be destroyed before the thread exits,
  // and the refund then reaches it like any other closed node.
  auto refund_q = [&]() {
    quota::refund(s_quota_tree, thread_mem_quota, total_cost);
  };

  Capability state_page = vm::alloc_pages(THREAD_STATE_PAGES);
  if (!capability_is_valid(state_page)) {
    refund_q();
    return fail_with(out_status, Status::NoMemory);
  }

  Capability stack_mem = vm::alloc_pages(stack_pages);
  if (!capability_is_valid(stack_mem)) {
    quota::owe(thread_mem_quota, vm::free_pages(state_page));
    quota::refund(s_quota_tree, thread_mem_quota, stack_bytes);
    return fail_with(out_status, Status::NoMemory);
  }

  // Build the user stack capability: bounded to [stack_base, stack_base +
  // stack_bytes), positioned at the top (stacks grow downward), and LOCAL.
  // Every capability derived from it -- every narrowed `csp` the switcher and
  // the trap path hand out -- inherits that, and the only memory a compartment
  // holds with StoreLocal is its thread stacks (compartment.cpp, `user_view`).
  // So a pointer into this stack can be kept on this stack and nowhere else:
  // not in a table, not in an allocation, not in another thread's hands.
  const uint64_t stack_base = capability_get_base(stack_mem);
  Capability user_sp = capability_restrict_levels(
      capability_set_address(stack_mem, stack_base + stack_bytes),
      perms::Global);

  // Build the kernel return stack capability inside the back of `state_page`:
  // bounded strictly to `[page_base + kstack_offset, page_base +
  // THREAD_STATE_COST)` so an overflow on the kernel stack traps before
  // touching `ThreadState` at the front of the allocation.
  const uint64_t page_base = capability_get_base(state_page);
  const size_t raw_kstack_bytes = THREAD_STATE_COST - sizeof(ThreadState);
  const size_t align_mask =
      __builtin_cheri_representable_alignment_mask(raw_kstack_bytes);
  const size_t kstack_bytes = raw_kstack_bytes & align_mask;
  const size_t kstack_offset = THREAD_STATE_COST - kstack_bytes;
  const uint64_t kstack_top_addr = page_base + kstack_offset + kstack_bytes;
  Capability kstack_top =
      capability_set_address(state_page, page_base + kstack_offset);
  kstack_top = capability_set_bounds(kstack_top, kstack_bytes);
  kstack_top = capability_set_address(kstack_top, kstack_top_addr);

  // Pre-populate a SwitchFrame at the top of the thread's kernel stack so that
  // `dispatch()` loads the new thread's state from its kernel stack through the
  // exact same path as resuming a halted thread.
  Capability kernel_sp =
      capability_set_address(kstack_top, kstack_top_addr - sizeof(SwitchFrame));
  SwitchFrame* frame = reinterpret_cast<SwitchFrame*>(kernel_sp);
  frame->sp = user_sp;
  frame->gp = entry_table;
  frame->tp = nullptr;
  for (size_t i = 0; i < 7; ++i) {
    frame->t[i] = nullptr;
  }
  for (size_t i = 0; i < 12; ++i) {
    frame->s[i] = nullptr;
  }
  for (size_t i = 0; i < 8; ++i) {
    frame->a[i] = nullptr;
  }
  frame->t[0] = hw_sentry;
  frame->a[0] = initial_arg;
  frame->active_kernel_sp = kstack_top;
  // `__thread_restore` ends in `ret`, and a return only goes through a return
  // sentry (toolchain/sentries), which only the hardware makes: the link of a
  // jump from just before `__thread_start` (switch.S).
  const Capability start_ra = __thread_start_link();
  if (capability_get_address(start_ra) !=
      capability_get_address(reinterpret_cast<Capability>(&__thread_start))) {
    debug::panic("thread::create: __thread_start_link does not link to __thread_start");
  }
  frame->ra = start_ra;

  ThreadState* t = reinterpret_cast<ThreadState*>(state_page);
  const uint64_t tid = __atomic_fetch_add(&s_next_tid, 1, __ATOMIC_RELAXED) + 1;
  t->self_page = state_page;
  t->tid = tid;
  t->flags = FLAG_LIVE;
  t->exit_status = 0;
  t->funding_quota = thread_mem_quota;
  t->stack_alloc = stack_mem;
  t->total_billed = total_cost;
  t->entry_sentry = entry_sentry;
  t->initial_arg = initial_arg;
  t->user_sp = user_sp;
  t->kernel_sp = kernel_sp;

  // Seal the handle bounded strictly to `sizeof(ThreadState)`.
  Capability handle = capability_set_bounds(state_page, sizeof(ThreadState));
  handle = capability_and_perms(handle, perms::Load | perms::Store |
                                            perms::LoadCapability |
                                            perms::LoadMutable);
  handle = sealing::seal_as(OType::Thread, handle);
  if (!capability_is_valid(handle)) {
    quota::owe(thread_mem_quota, vm::free_pages(stack_mem));
    quota::owe(thread_mem_quota, vm::free_pages(state_page));
    return fail_with(out_status, Status::InvalidCapability);
  }

  // Nothing ties the thread to its entry's compartment: if that is destroyed
  // and swept before the thread first runs, the sentry in its initial frame
  // loses its tag and `__thread_start` ends the thread (switch.S).

  // Thread creation and initial SwitchFrame: verify every capability seeded into the new thread's initial register frame
  // (`csp = user_sp`, `cgp = entry_table`, `ct0 = hw_sentry`,
  // `ca0 = initial_arg`, `cra = __thread_start`). The thread handle itself is
  // checked by the syscall gate on its way out.
  inspect::assert_user_capability(user_sp, "thread::create:user_sp");
  inspect::assert_user_capability(entry_table, "thread::create:entry_table");
  inspect::assert_user_capability(hw_sentry, "thread::create:hw_sentry");
  inspect::assert_user_capability(initial_arg, "thread::create:initial_arg");
  inspect::assert_user_capability(frame->ra, "thread::create:start_ra");

  __atomic_fetch_add(&s_live_threads, 1, __ATOMIC_RELAXED);

  if (out_status != nullptr) {
    *out_status = Status::Ok;
  }
  return handle;
}

// The exit path's entry to teardown (`__thread_exit_to_host`, switch.S).
extern "C" void __signetos_teardown_thread(ThreadState* t) {
  teardown_thread(t);
}

extern "C" Capability __signetos_thread_dispatch(Capability thread_handle,
                                                 SwitchFrame* saved_frame) {
  // A refused switch resumes the same context with the Status in its `a0`.
  auto fail = [&](Status s) -> Capability {
    saved_frame->a[0] =
        reinterpret_cast<Capability>(static_cast<uintptr_t>(s));
    return reinterpret_cast<Capability>(saved_frame);
  };

  ThreadState* t = unseal_thread(thread_handle);
  if (t == nullptr) {
    return fail(Status::InvalidCapability);
  }
  if (!capability_has_perms(thread_handle, perms::Load)) {
    return fail(Status::InsufficientPermission);
  }

  // Claim `t` before reading anything else of it: one compare-and-swap that
  // fails if it is running (on any hart) or exited, so two harts cannot both
  // take the same thread and reload the same frame.
  uint32_t old = __atomic_load_n(&t->flags, __ATOMIC_RELAXED);
  do {
    if ((old & (FLAG_RUNNING | FLAG_EXITED)) != 0) {
      return fail(Status::InvalidCapability);
    }
  } while (!__atomic_compare_exchange_n(&t->flags, &old,
                                        old | FLAG_RUNNING | FLAG_STARTED,
                                        false, __ATOMIC_ACQUIRE,
                                        __ATOMIC_RELAXED));

  SwitchFrame* next_frame = reinterpret_cast<SwitchFrame*>(t->kernel_sp);

  // `__thread_restore` re-derives the hart's kernel SP as
  // `frame + sizeof(SwitchFrame)`. Refuse to switch if the
  // frame's recorded `active_kernel_sp` disagrees: that would mean the frame
  // was not carved from `mscratchc` by `sys_thread_switch` / `thread::create`.
  if (!capability_is_valid(next_frame->active_kernel_sp) ||
      capability_get_address(next_frame->active_kernel_sp) !=
          capability_get_address(t->kernel_sp) + sizeof(SwitchFrame)) {
    __atomic_fetch_and(&t->flags, ~FLAG_RUNNING, __ATOMIC_RELEASE);
    return fail(Status::InvalidCapability);
  }

  // `saved_frame->active_kernel_sp` was written by `sys_thread_switch` at
  // push (asm_macros.h, FRAME LINK).

  // What the outgoing context sees in `a0` when it is resumed: 0, i.e.
  // `Status::Ok`, never the handle it passed in.
  saved_frame->a[0] = nullptr;

  // Release the outgoing context. This function runs on `prev`'s kernel page
  // (below `saved_frame`), so on more than one hart the clearing of
  // FLAG_RUNNING has to move to after this function's epilogue -- into
  // `sys_thread_switch` between the return from here and `__thread_restore`
  // -- or another hart may resume `prev` onto this frame while it is live.
  // One hart today: nobody can take `prev` before this hart has left.
  Cpu* c = cpu();
  ThreadState* prev = c->current;
  if (prev != nullptr) {
    prev->kernel_sp = reinterpret_cast<Capability>(saved_frame);
    __atomic_fetch_and(&prev->flags, ~FLAG_RUNNING, __ATOMIC_RELEASE);
  } else {
    c->host_kernel_sp = reinterpret_cast<Capability>(saved_frame);
  }

  c->current = t;
  set_utidc(c->hart_id, t->tid);

  // Only once the switch is committed, so a refused handle never shows up
  // (TRACE_SWITCH=1 builds only).
  debug::trace_switch(prev != nullptr ? prev->tid : 0, t->tid);

  // The incoming frame is reloaded as-is. Every register in it was either
  // seeded by `create()` (asserted there) or saved from the thread's own
  // register file, which CHERI monotonicity says it cannot have widened.
  //
  // `__thread_restore` leaves interrupts masked. Whatever the frame resumes
  // unmasks on its own way out, with the value its user context had: the
  // switcher's return path from its `ReturnFrame` (a thread parked by
  // `sys_thread_switch`, from a trap handler or not), `__thread_start` for a
  // new thread, and the host never.
  set_kernel_sp(next_frame->active_kernel_sp);
  return t->kernel_sp;
}

void exit(int exit_status) {
  Cpu* c = cpu();
  ThreadState* t = c->current;
  if (t == nullptr) {
    return;
  }
  t->exit_status = exit_status;
  t->flags = (t->flags & ~FLAG_RUNNING) | FLAG_EXITED;
  c->current = nullptr;
  set_utidc(c->hart_id, 0);

  Capability host_sp = c->host_kernel_sp;
  c->host_kernel_sp = nullptr;

  SwitchFrame* host_frame = reinterpret_cast<SwitchFrame*>(host_sp);
  host_frame->a[0] = nullptr;  // Status::Ok (0)
  set_kernel_sp(host_frame->active_kernel_sp);

  __thread_exit_to_host(t, host_sp);
}

Status kill(Capability thread_handle) {

  ThreadState* t = unseal_thread(thread_handle);
  if (t == nullptr) {
    return Status::InvalidCapability;
  }
  if (!capability_has_perms(thread_handle, perms::Store)) {
    return Status::InsufficientPermission;
  }
  // A thread that has never run is claimed with the same compare-and-swap as
  // `__signetos_thread_dispatch`, so a first dispatch and a kill cannot both
  // proceed, and torn down here. A thread that has run is only marked; it
  // calls `exit` itself when it next reaches its own code (unwind.cpp).
  uint32_t old = __atomic_load_n(&t->flags, __ATOMIC_RELAXED);
  uint32_t desired;
  do {
    if ((old & FLAG_EXITED) != 0) {
      return Status::InvalidCapability;  // already ending
    }
    desired = (old & FLAG_STARTED) == 0 ? old | FLAG_EXITED
                                        : old | FLAG_KILL_PENDING;
  } while (!__atomic_compare_exchange_n(&t->flags, &old, desired,
                                        false, __ATOMIC_ACQUIRE,
                                        __ATOMIC_RELAXED));
  if ((old & FLAG_STARTED) == 0) {
    teardown_thread(t);
  }
  return Status::Ok;
}

bool current_kill_pending() {
  ThreadState* t = cpu()->current;
  return t != nullptr &&
         (__atomic_load_n(&t->flags, __ATOMIC_ACQUIRE) & FLAG_KILL_PENDING) != 0;
}

uint64_t tid_of(Capability thread_handle) {
  ThreadState* t = unseal_thread(thread_handle);
  return t == nullptr ? 0 : t->tid;
}

uint64_t current_tid() {
  ThreadState* t = cpu()->current;
  return t == nullptr ? 0 : t->tid;
}

Capability current_entry_sentry() {
  ThreadState* t = cpu()->current;
  return t == nullptr ? nullptr : t->entry_sentry;
}

Capability current_user_stack() {
  ThreadState* t = cpu()->current;
  return t == nullptr ? nullptr : t->user_sp;
}

}  // namespace signetos::thread
