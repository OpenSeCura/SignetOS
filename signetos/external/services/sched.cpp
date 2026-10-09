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
 * sched.cpp - SignetOS User-Space CPU Bandwidth Scheduler Compartment
 *
 * The kernel holds no scheduling state: it provides `sys_thread_switch`, a
 * periodic tick on `IRQ_S_TIMER`, and re-dispatches this compartment's
 * dispatcher thread whenever a thread exits.
 *
 * OBJECTS
 *   quota_sched   One page per node, paid for by the caller's `node_funding`
 *                 VM quota. Handles are hardware-sealed with `OType::QuotaSched`:
 *                 `Load|Store` for the administrative (derive/destroy/register)
 *                 handle and `Load` for the operational (register only) handle.
 *   ThreadRec     Registered thread: its `OType::Thread` handle (the right
 *                 to `sys_thread_switch` to it), its node and accounting.
 *
 * ENTRY POINTS (each a separate `OType::EntryPoint`, published by name)
 *   sched.quota_derive     SchedDeriveRequest     Store on parent
 *   sched.quota_destroy    (quota)                Store on quota
 *   sched.thread_register  (thread, quota)        Load on quota
 *   sched.yield            ()                     give up the rest of the slice
 *   sched.block            (timeout_us)           sleep until woken (or timeout)
 *   sched.wake             (tid)                  wake a blocked thread by tid
 *   sched.thread_kill      (thread)               Store on thread: end it
 *   sched.self             ()                     the caller's tid
 *   sched.policy_register  (root, delegate)       Store on root
 *   sched.run              (kernel-created dispatcher thread; not published)
 *   (tick)                 bound to IRQ_S_TIMER; not published
 *
 * DISPATCH
 *   The dispatcher thread runs `pick(); sys_thread_switch(t)` forever. Every
 *   thread exit unwinds to the kernel's host context, which re-dispatches
 *   the dispatcher: its `sys_thread_switch` returns and `s_running` is the
 *   thread that has just exited. `yield` and the tick handler switch
 *   thread-to-thread directly and only ever update `s_running`. The
 *   dispatcher exits when nothing is registered, which ends the system.
 *
 * PREEMPTION
 *   The scheduler binds `IRQ_S_TIMER` (the kernel's fixed 10 ms tick) to
 *   `sched_tick_entry`. The handler runs on the interrupted thread's stack
 *   with interrupts masked: it charges the slice, picks, and if someone else
 *   should run it calls `sys_thread_switch` from inside the handler. The
 *   preempted thread stays parked in its handler until it is switched back to,
 *   when the handler returns and `sret` resumes it. The handler stands down
 *   while an entry point is mid-update (`s_busy`), while a foreign policy
 *   delegate runs, and when the interrupted context is the dispatcher itself;
 *   those cases catch up at the next tick or on their own.
 *
 * BLOCKING
 *   `block` marks the caller BLOCKED and picks someone else; a BLOCKED thread
 *   is invisible to `pick` until `wake` makes it READY again. `wake` is built
 *   to be called from interrupt context (a device driver, via whoever it
 *   notifies): it only flips one record, never picks or switches, and so
 *   needs no `s_busy` protection. The classic lost-wakeup race -- the event
 *   lands after the caller looked and before it blocked -- is closed by
 *   `wake_pending`: a wake that finds its target not BLOCKED is remembered,
 *   and `block` consumes it and returns at once. `block` writes BLOCKED
 *   before it reads `wake_pending`, and `wake` tests BLOCKED before it sets
 *   `wake_pending`, so whichever instruction the interrupt lands on, one of
 *   the two sides sees the other.
 *
 *   A `block` with a timeout also records `wake_at_us`; `expire` (run at the
 *   top of every `pick`) makes a BLOCKED thread whose time has come READY by
 *   the same compare-and-swap `wake` uses, so the two cannot both win, and
 *   `next_event` makes an idle CPU stop idling when the earliest one is due.
 *   A thread that keeps the CPU without yielding still gets ticked, and the
 *   tick picks, so a timeout is late by at most a tick.
 *
 * KILLING
 *   `thread_kill` asks the kernel to end a thread (`sys_thread_kill`, see
 *   unwind.hpp). The thread only ends once it runs, so a killed thread never
 *   sleeps: `thread_kill` wakes it as `wake` does, and every later `block`
 *   returns SCHED_KILLED at once. Its record is reaped like any exited
 *   thread's, or, if the kernel tore it down before it ever ran, on the next
 *   refused switch to it.
 *
 * IDLE
 *   When nothing is runnable the CPU idles in the scheduler (`idle_until`):
 *   a spin with `s_running` clear, so the tick has nothing to charge or
 *   preempt and nobody is billed for idle time, ended by the earliest period
 *   reset or by a wake. A thread that yields with its budget spent and
 *   nothing else to run idles there too, rather than running on borrowed
 *   time: spare bandwidth is not handed out, it is idled. The tick handler
 *   is the one exception -- it cannot spin masked -- so a thread that never
 *   yields keeps the CPU when nothing else is runnable.
 *
 * ORDERING
 *   Priority classes are strict (RT before Interactive before Batch). Within
 *   a class, nodes with a runnable thread take turns; within a node the
 *   node's policy picks the thread through the `PolicyRequest` contract
 *   (`abi.hpp`), which third-party delegates registered with
 *   `sched.policy_register` implement behind a sentry. A node whose budget
 *   for the current period is spent is skipped until the period resets.
 */

#include "runtime.hpp"

namespace signetos::user {
namespace {

// --- What `sched` asks `init` for (user/manifest.hpp) -------------------------
// The timer interrupt is the scheduler's clock; `trap_bind` is how it attaches
// to it; `thread_switch`/`thread_tid` are what dispatching is made of;
// `OType::QuotaSched` makes `quota_sched` handles; the VM entries fund
// the per-node pages. `naming.publish` is asked for because the scheduler
// publishes its own entry points as it mints them, rather than handing them
// all back in the handshake; `naming.lookup` is spare.
#define SCHED_MANIFEST(X)                                \
  M_IRQ(X, IRQ_TIMER, 5)                                 \
  M_OTYPE(X, SEAL_AUTH, ::signetos::OType::QuotaSched)   \
  M_SYSCALL(X, SYS_TRAP_BIND, trap_bind)                 \
  M_SYSCALL(X, SYS_TRAP_UNBIND, trap_unbind)             \
  M_SYSCALL(X, SYS_THREAD_SWITCH, thread_switch)         \
  M_SYSCALL(X, SYS_THREAD_TID, thread_tid)               \
  M_SYSCALL(X, SYS_THREAD_KILL, thread_kill)             \
  M_SYSCALL(X, SYS_VM_ALLOC, vm_allocate)                \
  M_SYSCALL(X, SYS_VM_DEALLOC, vm_deallocate)            \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)      \
  M_SYSCALL(X, SYS_SENTRY, sentry)                       \
  M_SERVICE(X, UART_SENTRY, "uart")                      \
  M_SERVICE_OPT(X, NAMING_LOOKUP, "naming.lookup")       \
  M_SERVICE(X, NAMING_PUBLISH, "naming.publish")
SIGNETOS_MANIFEST(SCHED_MANIFEST, 256 * 1024)

using init::PolicyRequest;
using init::PolicyView;

constexpr size_t MAX_THREADS = 128;
constexpr size_t MAX_NODES = 64;
constexpr size_t MAX_POLICIES = 16;
constexpr size_t MAX_VIEW = 32;  // threads one node offers a policy per pick

// `time` ticks per microsecond; populated from `SchedInterface::timebase_hz`
// (`/cpus` `timebase-frequency` in the DTB, fallback 10 MHz).
uint64_t s_ticks_per_us = 10;

constexpr uint32_t T_FREE = 0;
constexpr uint32_t T_READY = 1;
constexpr uint32_t T_RUNNING = 2;
constexpr uint32_t T_BLOCKED =
    3;  // in `block`; invisible to `pick` until woken

struct QuotaSched;

struct ThreadRec {
  Capability thread;        // sealed OType::Thread with Permit_Load
  QuotaSched* node;
  ThreadRec* next;          // node's thread list
  uint64_t tid;             // the kernel's id for it (sys_thread_tid)
  uint64_t runtime_us;
  uint64_t last_run_us;
  uint32_t state;
  uint32_t wake_pending;  // a wake arrived while not BLOCKED (file comment)
  uint64_t wake_at_us;    // BLOCKED with a timeout: READY again at this time
  bool timed_out;         // the last `block` ended by `expire`
  bool killed;            // `thread_kill` was called: `block` never sleeps it
};

// One node per page.
struct alignas(16) QuotaSched {
  struct {
    QuotaSched* parent;
    QuotaSched* first_child;
    QuotaSched* next_sibling;
    QuotaSched* prev_sibling;
    uint64_t child_count;
  } tree;

  // Bandwidth definition: budget C per period T (microseconds).
  uint32_t budget_us;
  uint32_t period_us;
  uint32_t delegated_budget_us;  // children's C, normalised to our T
  uint8_t priority_class;
  uint8_t pad0_[3];
  uint32_t deadline_us;
  uint32_t policy_id;
  Capability policy_delegate;    // nullptr for built-in policies

  // Runtime state.
  uint32_t remaining_budget_us;
  uint32_t active_thread_count;
  uint64_t last_replenish_tick;  // microseconds

  // Private bookkeeping.
  Capability node_page;          // this page, as returned by sys_vm_allocate
  Capability node_funding;       // the QuotaVm that paid for it
  ThreadRec* threads;
};
static_assert(sizeof(QuotaSched) <= vm::PAGE_SIZE);

struct Policy {
  Capability delegate;      // nullptr for the built-ins
  bool used;
};

// Scheduler state: funded from the compartment's own image (`.bss`).
Capability s_self_comp = nullptr;
Capability s_seal_auth = nullptr;
Capability s_gate_alloc = nullptr;
Capability s_gate_dealloc = nullptr;
Capability s_gate_switch = nullptr;
Capability s_gate_thread_tid = nullptr;
Capability s_gate_thread_kill = nullptr;
Capability s_gate_invoke = nullptr;
Capability s_uart = nullptr;

QuotaSched* s_root = nullptr;
QuotaSched* s_nodes[MAX_NODES];
size_t s_node_count = 0;
size_t s_node_cursor = 0;

ThreadRec s_threads[MAX_THREADS];
size_t s_registered = 0;

Policy s_policies[MAX_POLICIES];
bool s_in_delegate = false;
// An entry point is updating scheduler state on the current thread: the tick
// handler must not pick (it would see half-updated lists). Cleared across
// `sys_thread_switch`, since the thread that comes back may be anything.
bool s_busy = false;

ThreadRec* s_running = nullptr;
uint64_t s_slice_start_us = 0;

// Bumped by every `wake`, from interrupt context; `idle_until` polls it so an
// idle CPU notices a thread becoming runnable before the next period reset.
volatile uint64_t s_wakeups = 0;

alignas(16) PolicyView s_view[MAX_VIEW];

inline uint64_t now_us() {
  uint64_t t;
  __asm__ volatile("csrr %0, time" : "=r"(t));
  return t / s_ticks_per_us;
}

// Orders plain stores to scheduler globals against the handlers (tick, wake)
// that can land between any two instructions. Single hart: a compiler
// barrier is all that is needed.
inline void compiler_barrier() { __asm__ volatile("" ::: "memory"); }

inline uint32_t sat_sub(uint32_t a, uint64_t b) {
  return (b >= a) ? 0 : static_cast<uint32_t>(a - b);
}

template <typename T>
T* open_request(Capability arg) {
  if (!capability_is_valid(arg) || sealing::is_sealed(arg) ||
      capability_get_length(arg) < sizeof(T)) {
    return nullptr;
  }
  return reinterpret_cast<T*>(arg);
}

// --- Nodes -------------------------------------------------------------------

QuotaSched* node_for_page(uint64_t page_addr) {
  for (size_t i = 0; i < s_node_count; ++i) {
    if (capability_get_base(s_nodes[i]->node_page) == page_addr) {
      return s_nodes[i];
    }
  }
  return nullptr;
}

// Unseals a quota handle. `need_store`: the handle must be the
// administrative one. Returns the node or nullptr.
QuotaSched* open_quota(Capability handle, bool need_store) {
  Capability payload = sealing::unseal_with(s_seal_auth, handle);
  if (!capability_is_valid(payload) ||
      capability_get_length(payload) != vm::PAGE_SIZE ||
      (capability_get_perms(payload) & perms::Load) == 0) {
    return nullptr;
  }
  if (need_store && (capability_get_perms(payload) & perms::Store) == 0) {
    return nullptr;
  }
  return node_for_page(capability_get_base(payload));
}

Capability seal_node(QuotaSched* node, bool admin) {
  const uint64_t p = admin ? (perms::Load | perms::Store) : perms::Load;
  Capability obj = capability_and_perms(node->node_page, p);
  return sealing::seal_with(s_seal_auth, obj);
}

// Budget available to the node's own threads: what it has not delegated.
inline uint32_t own_budget(const QuotaSched* n) {
  return sat_sub(n->budget_us, n->delegated_budget_us);
}

// Share of the parent's period a child of (C, T) consumes, rounded up.
inline uint64_t normalised_share(uint64_t c_child, uint64_t t_child,
                                 uint64_t t_parent) {
  return (c_child * t_parent + t_child - 1) / t_child;
}

void replenish(QuotaSched* n, uint64_t now) {
  if (n->period_us == 0) {
    return;
  }
  const uint64_t elapsed = now - n->last_replenish_tick;
  if (elapsed >= n->period_us) {
    n->last_replenish_tick = now - (elapsed % n->period_us);
    n->remaining_budget_us = own_budget(n);
  }
}

QuotaSched* alloc_node(Capability funding, QuotaSched* parent) {
  if (s_node_count >= MAX_NODES) {
    return nullptr;
  }
  using FnAlloc = decltype(&sys_vm_allocate);
  Capability page =
      syscall::call<FnAlloc>(s_gate_invoke, s_gate_alloc, s_self_comp, funding,
                             vm::PAGE_SIZE, FLAG_ZERO);
  if (!capability_is_valid(page)) {
    return nullptr;
  }
  QuotaSched* n = reinterpret_cast<QuotaSched*>(page);
  n->node_page = page;
  n->node_funding = funding;
  n->threads = nullptr;
  n->tree.parent = parent;
  n->tree.first_child = nullptr;
  n->tree.prev_sibling = nullptr;
  n->tree.next_sibling = nullptr;
  n->tree.child_count = 0;
  if (parent != nullptr) {
    n->tree.next_sibling = parent->tree.first_child;
    if (parent->tree.first_child != nullptr) {
      parent->tree.first_child->tree.prev_sibling = n;
    }
    parent->tree.first_child = n;
    parent->tree.child_count += 1;
  }
  s_nodes[s_node_count++] = n;
  return n;
}

void free_node(QuotaSched* n) {
  QuotaSched* parent = n->tree.parent;
  if (parent != nullptr) {
    if (n->tree.prev_sibling != nullptr) {
      n->tree.prev_sibling->tree.next_sibling = n->tree.next_sibling;
    } else {
      parent->tree.first_child = n->tree.next_sibling;
    }
    if (n->tree.next_sibling != nullptr) {
      n->tree.next_sibling->tree.prev_sibling = n->tree.prev_sibling;
    }
    parent->tree.child_count -= 1;
    parent->delegated_budget_us = sat_sub(
        parent->delegated_budget_us,
        normalised_share(n->budget_us, n->period_us, parent->period_us));
  }
  for (size_t i = 0; i < s_node_count; ++i) {
    if (s_nodes[i] == n) {
      s_nodes[i] = s_nodes[s_node_count - 1];
      s_nodes[s_node_count - 1] = nullptr;
      s_node_count -= 1;
      break;
    }
  }
  Capability page = n->node_page;
  Capability funding = n->node_funding;
  // The page is quarantined by the kernel, not reused; scrub what we can.
  n->node_page = nullptr;
  n->node_funding = nullptr;
  using FnDealloc = decltype(&sys_vm_deallocate);
  syscall::call<FnDealloc>(s_gate_invoke, s_gate_dealloc, s_self_comp, funding,
                           page);
}

// --- Policies ----------------------------------------------------------------

bool policy_known(uint32_t id) {
  return id < MAX_POLICIES && s_policies[id].used;
}

// Built-ins. They see exactly what a foreign delegate would.
void policy_round_robin(PolicyRequest* req) {
  // Least recently run first.
  const PolicyView* v = reinterpret_cast<const PolicyView*>(req->threads);
  uint64_t best = ~0ULL;
  for (uint32_t i = 0; i < req->count; ++i) {
    if (v[i].runnable && v[i].last_run_us < best) {
      best = v[i].last_run_us;
      req->pick = v[i].tid;
    }
  }
}

void policy_fifo(PolicyRequest* req) {
  // Oldest registration first (tids are issued in order).
  const PolicyView* v = reinterpret_cast<const PolicyView*>(req->threads);
  uint64_t best = ~0ULL;
  for (uint32_t i = 0; i < req->count; ++i) {
    if (v[i].runnable && v[i].tid < best) {
      best = v[i].tid;
      req->pick = v[i].tid;
    }
  }
}

void policy_edf(PolicyRequest* req) {
  // Earliest (last run + relative deadline) first; equal deadlines degrade
  // to least-recently-run.
  const PolicyView* v = reinterpret_cast<const PolicyView*>(req->threads);
  uint64_t best = ~0ULL;
  for (uint32_t i = 0; i < req->count; ++i) {
    const uint64_t due = v[i].last_run_us + v[i].deadline_us;
    if (v[i].runnable && due < best) {
      best = due;
      req->pick = v[i].tid;
    }
  }
}

void run_policy(QuotaSched* n, PolicyRequest* req) {
  req->pick = 0;
  const uint32_t id = n->policy_id;
  if (id == init::POLICY_SCHED_FIFO) {
    policy_fifo(req);
  } else if (id == init::POLICY_SCHED_EDF) {
    policy_edf(req);
  } else if (id < init::POLICY_SCHED_FIRST_CUSTOM) {
    policy_round_robin(req);
  } else if (policy_known(id) && capability_is_valid(n->policy_delegate)) {
    // Foreign delegate: a Load-only view, and the tick handler stands down
    // while it runs (it may not switch threads from under us).
    Capability req_cap = reinterpret_cast<Capability>(req);
    req_cap = capability_set_bounds(req_cap, sizeof(PolicyRequest));
    using FnInvoke = decltype(&sys_compartment_invoke);
    s_in_delegate = true;
    reinterpret_cast<FnInvoke>(s_gate_invoke)(n->policy_delegate, req_cap);
    s_in_delegate = false;
  }
}

// --- Threads -----------------------------------------------------------------

// A thread's `tid` is the kernel's id for it (`sys_thread_tid`), fetched at
// registration; the scheduler has no numbering of its own.

ThreadRec* find_tid(QuotaSched* n, uint64_t tid) {
  for (ThreadRec* t = n->threads; t != nullptr; t = t->next) {
    if (t->tid == tid) {
      return t;
    }
  }
  return nullptr;
}

// Same, across every node.
ThreadRec* find_registered(uint64_t tid) {
  for (size_t i = 0; i < MAX_THREADS; ++i) {
    if (s_threads[i].state != T_FREE && s_threads[i].tid == tid) {
      return &s_threads[i];
    }
  }
  return nullptr;
}

void charge_running(uint64_t now) {
  if (s_running == nullptr) {
    return;
  }
  const uint64_t used = now - s_slice_start_us;
  s_running->runtime_us += used;
  s_running->node->remaining_budget_us =
      sat_sub(s_running->node->remaining_budget_us, used);
  s_slice_start_us = now;
}

// The node's choice among its own ready threads, or nullptr.
ThreadRec* node_pick(QuotaSched* n, uint64_t now) {
  replenish(n, now);
  if (n->remaining_budget_us == 0 || n->threads == nullptr) {
    return nullptr;
  }
  uint32_t count = 0;
  ThreadRec* only = nullptr;
  for (ThreadRec* t = n->threads; t != nullptr && count < MAX_VIEW;
       t = t->next) {
    if (t->state != T_READY) {
      continue;
    }
    s_view[count].tid = t->tid;
    s_view[count].runtime_us = t->runtime_us;
    s_view[count].last_run_us = t->last_run_us;
    s_view[count].deadline_us = n->deadline_us;
    s_view[count].runnable = 1;
    only = t;
    count += 1;
  }
  if (count == 0) {
    return nullptr;
  }
  if (count == 1) {
    return only;
  }
  PolicyRequest req{};
  req.op = init::POLICY_PICK;
  req.count = count;
  req.now_us = now;
  req.node_id = capability_get_base(n->node_page);
  Capability view = reinterpret_cast<Capability>(&s_view[0]);
  view = capability_set_bounds(view, count * sizeof(PolicyView));
  req.threads = capability_and_perms(view, perms::Load);
  run_policy(n, &req);
  ThreadRec* chosen = find_tid(n, req.pick);
  if (chosen == nullptr || chosen->state != T_READY) {
    // Invalid answer from the policy: round-robin fallback.
    req.pick = 0;
    policy_round_robin(&req);
    chosen = find_tid(n, req.pick);
  }
  return chosen;
}

// Makes every BLOCKED thread whose timeout has passed READY again (BLOCKING
// in the header). The compare-and-swap is the one `wake` uses: whichever of
// the two gets there first, the other finds the thread no longer BLOCKED.
void expire(uint64_t now) {
  for (size_t i = 0; i < MAX_THREADS; ++i) {
    ThreadRec* t = &s_threads[i];
    if (t->wake_at_us == 0 || t->wake_at_us > now) {
      continue;
    }
    uint32_t expected = T_BLOCKED;
    if (__atomic_compare_exchange_n(&t->state, &expected, T_READY, false,
                                    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
      t->timed_out = true;
    }
    t->wake_at_us = 0;
  }
}

// The earliest timeout still pending, or `~0`.
uint64_t next_timeout() {
  uint64_t earliest = ~0ULL;
  for (size_t i = 0; i < MAX_THREADS; ++i) {
    const uint64_t at = s_threads[i].wake_at_us;
    if (at != 0 && s_threads[i].state == T_BLOCKED && at < earliest) {
      earliest = at;
    }
  }
  return earliest;
}

// Strict priority classes; round robin across nodes within a class.
ThreadRec* pick(uint64_t now) {
  expire(now);
  if (s_node_count == 0) {
    return nullptr;
  }
  for (uint8_t cls = init::PRIORITY_RT; cls <= init::PRIORITY_BATCH; ++cls) {
    for (size_t i = 0; i < s_node_count; ++i) {
      const size_t idx = (s_node_cursor + i) % s_node_count;
      QuotaSched* n = s_nodes[idx];
      if (n->priority_class != cls) {
        continue;
      }
      ThreadRec* t = node_pick(n, now);
      if (t != nullptr) {
        s_node_cursor = idx + 1;
        return t;
      }
    }
  }
  return nullptr;
}

// Earliest time any node with a ready thread gets budget back (or `now` if
// something is runnable; `~0` if nothing is registered).
uint64_t next_replenish(uint64_t now) {
  uint64_t earliest = ~0ULL;
  for (size_t i = 0; i < s_node_count; ++i) {
    QuotaSched* n = s_nodes[i];
    bool ready = false;
    for (ThreadRec* t = n->threads; t != nullptr; t = t->next) {
      if (t->state == T_READY) {
        ready = true;
        break;
      }
    }
    if (!ready || n->period_us == 0) {
      continue;
    }
    const uint64_t at = n->last_replenish_tick + n->period_us;
    if (at < earliest) {
      earliest = at;
    }
  }
  return earliest < now ? now : earliest;
}

// When an idle CPU has something to look at again: the earliest period reset
// of a node with a ready thread, or the earliest timeout of a blocked one.
uint64_t next_event(uint64_t now) {
  const uint64_t replenish = next_replenish(now);
  const uint64_t timeout = next_timeout();
  const uint64_t at = timeout < replenish ? timeout : replenish;
  return at < now ? now : at;
}

void reap(ThreadRec* t, uint64_t now);

// Hands the CPU to `t`. Returns 0 when something switches back to the caller.
//
// A refused switch means one of two things. Either `t` is gone (it exited or
// was killed, and the kernel no longer knows its handle as a live thread):
// then nothing ran, `t` is reaped here, and the caller gets back the state it
// had, `s_busy` held, to pick again; the kernel's `Status` is returned. Or `t`
// is the thread running right now, i.e. the caller itself under a stale
// `s_running`: a tick can land between the stores below and the kernel
// masking interrupts, see `s_running == t` and act on it before it is true,
// and if it picks the interrupted thread the kernel refuses, as it is running.
// The kernel reports both as InvalidCapability; `sys_thread_tid` tells them
// apart, 0 only for a dead thread. For a live one `s_running = t` and
// `t->state = T_RUNNING` are already right, so that case reports success.
uint64_t switch_to(ThreadRec* t, uint64_t now) {
  ThreadRec* const prev = s_running;
  t->state = T_RUNNING;
  t->last_run_us = now;
  s_running = t;
  s_slice_start_us = now;
  s_busy = false;
  using FnSwitch = decltype(&sys_thread_switch);
  const uint64_t status =
      syscall::call<FnSwitch>(s_gate_invoke, s_gate_switch, t->thread);
  if (status != 0) {
    using FnThreadTid = decltype(&sys_thread_tid);
    if (syscall::call<FnThreadTid>(s_gate_invoke, s_gate_thread_tid,
                                   t->thread) != 0) {
      return 0;  // alive, so it is us: nothing to undo
    }
    s_busy = true;
    reap(t, now);  // clears `s_running`, which was `t`
    s_running = prev;
    s_slice_start_us = now;
  }
  // Back on this thread: whoever switched to us left `s_busy` clear.
  return status;
}

// Idles on the current thread (`cur`, or nullptr for the dispatcher) until
// `at` or a wake, whichever is first, and returns the time afterwards. With
// `s_running` clear the tick handler sees nothing to charge or preempt and
// stands down (its `cur == nullptr` check); ticks and device interrupts are
// still taken, which is how a wake gets in. `wfi` would do here instead of a
// spin -- everything runs in S-mode -- but a spin keeps the time base simple.
// Callers hold `s_busy` on entry and get it back on return. The barriers pin
// the store order: a tick landing anywhere in here sees either `s_running ==
// nullptr` or `s_busy`, never a live `s_running` with a stale slice start.
uint64_t idle_until(ThreadRec* cur, uint64_t at) {
  const uint64_t seen = s_wakeups;
  s_running = nullptr;
  compiler_barrier();
  s_busy = false;
  compiler_barrier();
  while (now_us() < at && s_wakeups == seen) {
    compiler_barrier();
  }
  s_busy = true;
  compiler_barrier();
  const uint64_t now = now_us();
  s_slice_start_us = now;  // the idle time is nobody's
  s_running = cur;
  compiler_barrier();
  return now;
}

void reap(ThreadRec* t, uint64_t now) {
  charge_running(now);
  QuotaSched* n = t->node;
  ThreadRec** link = &n->threads;
  while (*link != nullptr && *link != t) {
    link = &(*link)->next;
  }
  if (*link == t) {
    *link = t->next;
  }
  if (n->active_thread_count > 0) {
    n->active_thread_count -= 1;
  }
  t->thread = nullptr;
  t->node = nullptr;
  t->next = nullptr;
  t->state = T_FREE;
  t->wake_at_us = 0;
  t->killed = false;
  if (s_registered > 0) {
    s_registered -= 1;
  }
  if (s_running == t) {
    s_running = nullptr;
  }
}

// Marks scheduler state as mid-update for the current thread. Not held
// across `switch_to` (which clears the flag itself before switching).
struct BusyScope {
  BusyScope() { s_busy = true; }
  ~BusyScope() { s_busy = false; }
};

}  // namespace

// --- Entry points --------------------------------------------------------------

extern "C" int64_t sched_quota_derive_entry(Capability arg) {
  auto* req = open_request<init::SchedDeriveRequest>(arg);
  if (req == nullptr) {
    return init::SCHED_BAD_REQUEST;
  }
  BusyScope busy;
  req->out_quota = nullptr;
  QuotaSched* parent = open_quota(req->parent, true);
  if (parent == nullptr) {
    req->status = init::SCHED_PERMISSION;
    return req->status;
  }
  if (req->budget_us == 0 || req->period_us == 0 ||
      req->budget_us > req->period_us ||
      req->priority_class > init::PRIORITY_BATCH ||
      !sealing::is_sealed_as(OType::QuotaVm, req->node_funding)) {
    req->status = init::SCHED_BAD_REQUEST;
    return req->status;
  }
  const uint32_t policy = (req->policy_id == init::POLICY_SCHED_DEFAULT)
                              ? init::POLICY_SCHED_ROUND_ROBIN
                              : req->policy_id;
  if (!policy_known(policy)) {
    req->status = init::SCHED_UNKNOWN_POLICY;
    return req->status;
  }
  // Temporal conservation: C_c / T_c <= (C_p - D_p) / T_p.
  const uint64_t lhs = static_cast<uint64_t>(req->budget_us) * parent->period_us;
  const uint64_t rhs =
      static_cast<uint64_t>(own_budget(parent)) * req->period_us;
  if (lhs > rhs) {
    req->status = init::SCHED_BANDWIDTH;
    return req->status;
  }
  QuotaSched* n = alloc_node(req->node_funding, parent);
  if (n == nullptr) {
    req->status = init::SCHED_NO_MEMORY;
    return req->status;
  }
  n->budget_us = req->budget_us;
  n->period_us = req->period_us;
  n->delegated_budget_us = 0;
  n->priority_class = req->priority_class;
  n->deadline_us = (req->deadline_us != 0) ? req->deadline_us : req->period_us;
  n->policy_id = policy;
  n->policy_delegate = s_policies[policy].delegate;
  n->remaining_budget_us = req->budget_us;
  n->last_replenish_tick = now_us();
  n->active_thread_count = 0;
  parent->delegated_budget_us += static_cast<uint32_t>(
      normalised_share(req->budget_us, req->period_us, parent->period_us));
  // The parent's own threads just lost bandwidth; cap what is left.
  if (parent->remaining_budget_us > own_budget(parent)) {
    parent->remaining_budget_us = own_budget(parent);
  }
  const bool admin = (req->perms & perms::Store) != 0;
  Capability handle = seal_node(n, admin);
  if (!capability_is_valid(handle)) {
    free_node(n);
    req->status = init::SCHED_NO_MEMORY;
    return req->status;
  }
  req->out_quota = handle;
  req->status = init::SCHED_OK;
  return req->status;
}

extern "C" int64_t sched_quota_destroy_entry(Capability quota) {
  BusyScope busy;
  QuotaSched* n = open_quota(quota, true);
  if (n == nullptr || n == s_root) {
    return init::SCHED_PERMISSION;
  }
  if (n->tree.child_count != 0 || n->active_thread_count != 0 ||
      n->threads != nullptr) {
    return init::SCHED_BUSY;
  }
  free_node(n);
  return init::SCHED_OK;
}

extern "C" int64_t sched_thread_register_entry(Capability thread,
                                               Capability quota) {
  BusyScope busy;
  QuotaSched* n = open_quota(quota, false);
  if (n == nullptr) {
    return init::SCHED_PERMISSION;
  }
  if (!sealing::is_sealed_as(OType::Thread, thread) ||
      (capability_get_perms(thread) & perms::Load) == 0) {
    return init::SCHED_INVALID_THREAD;
  }
  // The thread's name is the kernel's id for it, fetched through the handle
  // we were handed rather than supplied by the caller, so nobody can file a
  // thread under another's number. 0: the kernel does not know this handle
  // as a live thread (stale, or forged).
  using FnThreadTid = decltype(&sys_thread_tid);
  const uint64_t tid =
      syscall::call<FnThreadTid>(s_gate_invoke, s_gate_thread_tid, thread);
  if (tid == 0 || find_registered(tid) != nullptr) {
    return init::SCHED_INVALID_THREAD;
  }
  ThreadRec* rec = nullptr;
  for (size_t i = 0; i < MAX_THREADS; ++i) {
    if (s_threads[i].state == T_FREE) {
      rec = &s_threads[i];
      break;
    }
  }
  if (rec == nullptr) {
    return init::SCHED_FULL;
  }
  rec->thread = thread;
  rec->node = n;
  rec->tid = tid;
  rec->runtime_us = 0;
  rec->last_run_us = 0;
  rec->wake_pending = 0;
  rec->wake_at_us = 0;
  rec->timed_out = false;
  rec->killed = false;
  rec->state = T_READY;
  rec->next = n->threads;
  n->threads = rec;
  n->active_thread_count += 1;
  s_registered += 1;
  return static_cast<int64_t>(rec->tid);
}

extern "C" int64_t sched_policy_register_entry(Capability root,
                                               Capability delegate) {
  BusyScope busy;
  if (open_quota(root, true) != s_root) {
    return init::SCHED_PERMISSION;
  }
  if (!sealing::is_sealed_as(OType::EntryPoint, delegate)) {
    return init::SCHED_BAD_REQUEST;
  }
  for (uint32_t id = init::POLICY_SCHED_FIRST_CUSTOM; id < MAX_POLICIES; ++id) {
    if (!s_policies[id].used) {
      s_policies[id].used = true;
      s_policies[id].delegate = delegate;
      return static_cast<int64_t>(id);
    }
  }
  return init::SCHED_FULL;
}

// Called in the yielding thread's own context (through the domain switcher).
extern "C" int64_t sched_yield_entry() {
  ThreadRec* cur = s_running;
  if (cur == nullptr || s_in_delegate) {
    return 0;
  }
  s_busy = true;
  uint64_t now = now_us();
  charge_running(now);
  cur->state = T_READY;
  for (;;) {
    ThreadRec* next = pick(now);
    if (next == cur) {
      cur->state = T_RUNNING;  // still the best choice: keep going
      s_busy = false;
      return 0;
    }
    if (next != nullptr) {
      // `switch_to` clears s_busy before switching.
      if (switch_to(next, now) == 0) {
        // Resumed by a later switch back to `cur`; `s_running` is already `cur`.
        return 0;
      }
      continue;  // `next` was dead and is reaped: pick again
    }
    // Every ready node -- ours included -- is out of budget for this period:
    // idle until the earliest reset instead of running on borrowed time.
    now = idle_until(cur, next_event(now));
  }
}

// The body of `block`: called holding `s_busy`, returns with it clear, once
// `cur` has been woken (or timed out, by `expire`).
void block_until_woken(ThreadRec* cur, uint64_t now) {
  // BLOCKED must be visible before we look at `wake_pending`: a wake landing
  // after this store flips us back to READY, one landing before it left the
  // pending flag, and the test below catches either.
  __atomic_store_n(&cur->state, T_BLOCKED, __ATOMIC_SEQ_CST);
  for (;;) {
    if (__atomic_exchange_n(&cur->wake_pending, 0u, __ATOMIC_SEQ_CST) != 0 ||
        __atomic_load_n(&cur->state, __ATOMIC_SEQ_CST) != T_BLOCKED) {
      cur->state = T_RUNNING;  // woken already: nothing to wait for
      s_busy = false;
      return;
    }
    ThreadRec* next = pick(now);
    if (next == cur) {
      // A wake got in between the test above and the pick.
      cur->state = T_RUNNING;
      s_busy = false;
      return;
    }
    if (next != nullptr) {
      if (switch_to(next, now) == 0) {
        // Back here because a `wake` made us READY and someone picked us;
        // `switch_to` on their side already made us RUNNING.
        return;
      }
      continue;  // `next` was dead and is reaped: look again
    }
    // Nothing runnable: idle until the earliest period reset, timeout or
    // wake (`~0`, i.e. a wake only, if every thread is blocked for good).
    now = idle_until(cur, next_event(now));
  }
}

// Called in the blocking thread's own context. Returns when a `wake` for
// this thread has been seen: either one that was already pending, or one
// that made us READY again and got us picked -- or when `timeout_us` ran out
// first. See BLOCKING in the header. `timeout_us == 0` blocks without a
// timeout.
extern "C" int64_t sched_block_entry(uint64_t timeout_us) {
  ThreadRec* cur = s_running;
  if (cur == nullptr || s_in_delegate) {
    return init::SCHED_INVALID_THREAD;
  }
  if (__atomic_load_n(&cur->killed, __ATOMIC_SEQ_CST)) {
    return init::SCHED_KILLED;  // a killed thread never sleeps
  }
  s_busy = true;
  const uint64_t now = now_us();
  charge_running(now);
  cur->timed_out = false;
  cur->wake_at_us = 0;
  if (timeout_us != 0) {
    const uint64_t at = now + timeout_us;
    cur->wake_at_us = at < now ? ~0ULL : at;
  }
  block_until_woken(cur, now);
  cur->wake_at_us = 0;
  if (__atomic_load_n(&cur->killed, __ATOMIC_SEQ_CST)) {
    return init::SCHED_KILLED;  // woken by `thread_kill`
  }
  return cur->timed_out ? init::SCHED_TIMED_OUT : init::SCHED_OK;
}

// Wakes the thread with `tid`. Safe to call from interrupt context, in the
// middle of any other entry point: it touches one record and the wake
// counter, and never picks or switches.
extern "C" int64_t sched_wake_entry(uint64_t tid) {
  ThreadRec* t = find_registered(tid);
  if (t == nullptr) {
    return init::SCHED_INVALID_THREAD;
  }
  uint32_t expected = T_BLOCKED;
  if (!__atomic_compare_exchange_n(&t->state, &expected, T_READY, false,
                                   __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
    // Not blocked (READY, RUNNING, or about to block): remember the wake so
    // the next `block` returns at once instead of sleeping through it.
    __atomic_store_n(&t->wake_pending, 1u, __ATOMIC_SEQ_CST);
  }
  s_wakeups = s_wakeups + 1;  // ends any `idle_until` in progress
  return init::SCHED_OK;
}

// Ends the thread behind `thread` (needs Store) through `sys_thread_kill`,
// then wakes it so it runs to where the kernel ends it (KILLING above). Like
// `wake`, this only touches one record and the wake counter, so it is safe
// from interrupt context.
extern "C" int64_t sched_thread_kill_entry(Capability thread) {
  if (!sealing::is_sealed_as(OType::Thread, thread)) {
    return init::SCHED_INVALID_THREAD;
  }
  // The id first: a thread that never ran is torn down by the kill.
  using FnThreadTid = decltype(&sys_thread_tid);
  const uint64_t tid =
      syscall::call<FnThreadTid>(s_gate_invoke, s_gate_thread_tid, thread);
  using FnThreadKill = decltype(&sys_thread_kill);
  const uint64_t st =
      syscall::call<FnThreadKill>(s_gate_invoke, s_gate_thread_kill, thread);
  if (st != static_cast<uint64_t>(Status::Ok)) {
    return st == static_cast<uint64_t>(Status::InsufficientPermission)
               ? init::SCHED_PERMISSION
               : init::SCHED_INVALID_THREAD;
  }
  ThreadRec* t = tid != 0 ? find_registered(tid) : nullptr;
  if (t == nullptr) {
    return init::SCHED_OK;  // not registered with us
  }
  // `killed` is set before the wake. A full `wake` is needed, not just the
  // BLOCKED -> READY flip: a kill from interrupt context can land between
  // `block`'s test of `killed` and the thread going to sleep, and only
  // `wake_pending` makes that sleep return at once.
  __atomic_store_n(&t->killed, true, __ATOMIC_SEQ_CST);
  sched_wake_entry(tid);
  return init::SCHED_OK;
}

// The caller's own tid: what it hands to whoever is going to `wake` it.
extern "C" uint64_t sched_self_entry() {
  return s_running != nullptr ? s_running->tid : 0;
}

// IRQ_S_TIMER handler (kernel trap ABI: a0-a3 = scause/stval/sepc/stval2,
// ca4 = this compartment's table slice). Runs masked on the interrupted
// thread's stack; `cgp` is our table, so globals resolve as usual.
extern "C" uint64_t sched_tick_entry(uint64_t scause, uint64_t stval,
                                     uint64_t sepc, uint64_t stval2,
                                     Capability cap_table_rw) {
  (void)scause;
  (void)stval;
  (void)sepc;
  (void)stval2;
  (void)cap_table_rw;
  ThreadRec* cur = s_running;
  // Nothing to do if the dispatcher itself was interrupted (it has its own
  // loop), or if scheduler state is mid-update on the interrupted thread.
  if (cur == nullptr || s_busy || s_in_delegate) {
    return 0;
  }
  s_busy = true;
  const uint64_t now = now_us();
  charge_running(now);
  // Only a RUNNING thread is demoted and only a READY one restored: the
  // interrupted thread is always RUNNING here (`block` holds `s_busy`), but
  // a BLOCKED record must never be turned back into a runnable one by us.
  if (cur->state == T_RUNNING) {
    cur->state = T_READY;
  }
  ThreadRec* next = pick(now);
  if (next == nullptr || next == cur) {
    if (cur->state == T_READY) {
      cur->state = T_RUNNING;  // work-conserving: a handler cannot idle
    }
    s_busy = false;
    return 0;
  }
  // Switch from inside the handler. `cur` stays parked here, masked, until
  // someone switches back to it; then this returns and `sret` resumes it.
  if (switch_to(next, now) != 0) {
    // `next` was dead and is reaped. Keep running `cur`; the next tick picks.
    if (cur->state == T_READY) {
      cur->state = T_RUNNING;
    }
    s_busy = false;
  }
  return 0;
}

// The dispatcher thread (`sched.run`), created and re-dispatched by the kernel.
extern "C" uint64_t sched_run_entry(Capability arg) {
  (void)arg;
  print(s_gate_invoke, s_uart, "[sched]    Dispatcher running\n");
  for (;;) {
    s_busy = true;
    uint64_t now = now_us();
    if (s_running != nullptr) {
      reap(s_running, now);  // our last switch returned: that thread exited
    }
    if (s_registered == 0) {
      s_busy = false;
      break;
    }
    ThreadRec* t = pick(now);
    if (t == nullptr) {
      // Every ready thread's node is out of budget, or everything is blocked:
      // idle until the earliest period reset or a wake, whichever is first.
      idle_until(nullptr, next_event(now));
      continue;
    }
    const uint64_t status = switch_to(t, now);
    if (status != 0) {
      // Refused: `t->thread` was not a live, halted thread. `switch_to` has
      // reaped it and left `s_running` clear, so the next round picks afresh.
      print_dec(s_gate_invoke, s_uart,
                "[sched]    thread_switch refused, status ", status,
                "; the thread is unregistered\n");
    }
  }
  print(s_gate_invoke, s_uart,
        "[sched]    No registered threads left; dispatcher exiting\n");
  return 0;
}

extern "C" int64_t compartment_main(Capability arg) {
  Capability* rw = rw_table();

  s_self_comp = rw[compartment::SLOT_SELF];
  Capability vm_quota = rw[compartment::SLOT_VM_QUOTA];
  Capability timer_irq_auth = rw[SLOT_IRQ_TIMER];
  s_seal_auth = rw[SLOT_SEAL_AUTH];
  Capability gate_trap_bind = rw[SLOT_SYS_TRAP_BIND];
  Capability gate_sentry = rw[SLOT_SYS_SENTRY];
  Capability naming_publish = rw[SLOT_NAMING_PUBLISH];
  s_gate_alloc = rw[SLOT_SYS_VM_ALLOC];
  s_gate_dealloc = rw[SLOT_SYS_VM_DEALLOC];
  s_gate_switch = rw[SLOT_SYS_THREAD_SWITCH];
  s_gate_thread_tid = rw[SLOT_SYS_THREAD_TID];
  s_gate_thread_kill = rw[SLOT_SYS_THREAD_KILL];
  s_gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  s_uart = rw[SLOT_UART_SENTRY];

  if (!sealing::is_sealed_as(OType::Compartment, s_self_comp) ||
      !sealing::is_sealed_as(OType::QuotaVm, vm_quota) ||
      !sealing::is_sealed_as(OType::Trap, timer_irq_auth) ||
      !capability_has_perms(s_seal_auth, perms::Seal | perms::Unseal) ||
      !sealing::is_sealed_as(OType::EntryPoint, naming_publish)) {
    return -1;
  }
  auto* iface = open_request<init::SchedInterface>(arg);
  if (iface == nullptr) {
    return -1;
  }
  if (iface->timebase_hz >= 1'000'000) {
    s_ticks_per_us = iface->timebase_hz / 1'000'000;
  }
  iface->root_quota = nullptr;
  iface->run = nullptr;

  // 1. Built-in policy catalogue.
  for (size_t i = 0; i < MAX_POLICIES; ++i) {
    s_policies[i] = Policy{};
  }
  s_policies[init::POLICY_SCHED_ROUND_ROBIN].used = true;
  s_policies[init::POLICY_SCHED_FIFO].used = true;
  s_policies[init::POLICY_SCHED_EDF].used = true;

  // 3. Root node: the whole machine, funded from our own VM quota.
  s_root = alloc_node(vm_quota, nullptr);
  if (s_root == nullptr) {
    return -1;
  }
  s_root->budget_us = init::SCHED_ROOT_PERIOD_US;
  s_root->period_us = init::SCHED_ROOT_PERIOD_US;
  s_root->delegated_budget_us = 0;
  s_root->priority_class = init::PRIORITY_INTERACTIVE;
  s_root->deadline_us = init::SCHED_ROOT_PERIOD_US;
  s_root->policy_id = init::POLICY_SCHED_ROUND_ROBIN;
  s_root->policy_delegate = nullptr;
  s_root->remaining_budget_us = s_root->budget_us;
  s_root->last_replenish_tick = now_us();
  s_root->active_thread_count = 0;

  // 4. Entry points, published by name; `run` goes back to init only.
  auto entry = [&](const void* fn) {
    return mint_entry(s_gate_invoke, gate_sentry, s_self_comp, fn);
  };
  Capability e_derive = entry(reinterpret_cast<const void*>(&sched_quota_derive_entry));
  Capability e_destroy = entry(reinterpret_cast<const void*>(&sched_quota_destroy_entry));
  Capability e_register = entry(reinterpret_cast<const void*>(&sched_thread_register_entry));
  Capability e_yield = entry(reinterpret_cast<const void*>(&sched_yield_entry));
  Capability e_block = entry(reinterpret_cast<const void*>(&sched_block_entry));
  Capability e_wake = entry(reinterpret_cast<const void*>(&sched_wake_entry));
  Capability e_kill = entry(reinterpret_cast<const void*>(&sched_thread_kill_entry));
  Capability e_self = entry(reinterpret_cast<const void*>(&sched_self_entry));
  Capability e_policy = entry(reinterpret_cast<const void*>(&sched_policy_register_entry));
  Capability e_run = entry(reinterpret_cast<const void*>(&sched_run_entry));
  publish_name(s_gate_invoke, naming_publish, "sched.quota_derive", e_derive);
  publish_name(s_gate_invoke, naming_publish, "sched.quota_destroy", e_destroy);
  publish_name(s_gate_invoke, naming_publish, "sched.thread_register", e_register);
  publish_name(s_gate_invoke, naming_publish, "sched.yield", e_yield);
  publish_name(s_gate_invoke, naming_publish, "sched.block", e_block);
  publish_name(s_gate_invoke, naming_publish, "sched.wake", e_wake);
  publish_name(s_gate_invoke, naming_publish, "sched.thread_kill", e_kill);
  publish_name(s_gate_invoke, naming_publish, "sched.self", e_self);
  publish_name(s_gate_invoke, naming_publish, "sched.policy_register", e_policy);

  iface->root_quota = seal_node(s_root, true);
  iface->run = e_run;

  // 5. Preemption: the kernel's tick is delivered to us from now on.
  Capability e_tick = entry(reinterpret_cast<const void*>(&sched_tick_entry));
  using FnTrapBind = decltype(&sys_trap_bind);
  syscall::call<FnTrapBind>(s_gate_invoke, gate_trap_bind, s_self_comp,
                            timer_irq_auth, e_tick);

  print(s_gate_invoke, s_uart,
        "[sched]    Scheduler online: root quota minted, sched.* published, "
        "tick bound\n");
  return 0;
}

}  // namespace signetos::user
