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

// THIS IS STILL A DUMB AND EARLY PROTOTYPE

/*
 * sched.cpp - SignetOS User-Space CPU Bandwidth Scheduler Compartment
 *
 * The kernel holds no scheduling state: it provides `sys_thread_switch`, a
 * periodic tick, and re-dispatches this compartment's dispatcher thread
 * whenever a thread exits. Every interrupt comes here (irq.hpp): it wakes a
 * thread of this compartment's (thread.hpp, THE INTERRUPT HANDLER).
 *
 * OBJECTS
 *   quota_sched   One page per node, paid for by the caller's `node_funding`
 *                 VM quota. Handles are hardware-sealed with
 * `OType::QuotaSched`. There is one kind: whoever holds it can derive from the
 * node, register threads on it and query it. Destroying a node takes its
 * parent's handle (DESTROYING). ThreadRec     Registered thread: its
 * `OType::Thread` handle (the right to `sys_thread_switch` to it), its node and
 * its state.
 *
 * ENTRY POINTS (each a separate `OType::EntryPoint`, published by name)
 *   sched.quota_derive     SchedDeriveRequest     the parent's handle
 *   sched.quota_destroy    (parent, child)        the parent's handle
 *   sched.quota_query      (quota, SchedQueryRequest)
 *   sched.thread_register  (thread, quota)        put a thread on a node
 *   sched.yield            ()                     give up the rest of the slice
 *   sched.block            (timeout_us)           sleep until woken (or
 * timeout) sched.wake             (tid)                  wake a blocked thread
 * by tid sched.thread_kill      (thread)               Store on thread: end it
 *   sched.lock_wait        (word, seen)           wait for a lock (LOCKS)
 *   sched.lock_wake        (word)                 hand a lock to its next owner
 *   sched.run              (kernel-created dispatcher thread; not published)
 *   (interrupt)            the interrupt handler's thread; not published
 *   sched.irq_route        (source)               route a device; `init` only
 *   sched.irq_wait         (timeout_us)           one per route, for its driver
 *                                                 only (DEVICE INTERRUPTS)
 *
 * ORDERING
 *   `pick` chooses among the threads that can run: those on a node with
 *   budget left that are READY, or that wait for a lock whose owner can run
 *   in their place (LOCKS). Priority classes are strict (RT before
 *   Interactive before Batch). Within a class the node served longest ago
 *   goes first, and within a node the thread chosen longest ago. A child's
 *   class is never more urgent than its parent's.
 *
 * BUDGETS
 *   A node gets its budget C back every period T. The running thread's node
 *   is charged at every tick and every switch, and `pick` passes over a node
 *   with nothing left, so a node can overrun by up to a tick (the kernel's
 *   fixed 10 ms). The overrun is carried into the next periods as a debt of
 *   at most a tick, so over time a node gets its share even when its budget
 *   is small next to the tick. Time a thread gets only because nothing else
 *   can run (the tick handler lets it run on, IDLE) is spare, and like idle
 *   time it is billed to nobody. Admission (`quota_derive`) keeps what a
 *   parent hands out within what it has not handed out already.
 *
 * DISPATCH
 *   The dispatcher thread runs `pick(); sys_thread_switch(t)` forever. Every
 *   thread exit unwinds to the kernel's host context, which re-dispatches
 *   the dispatcher: its `sys_thread_switch` returns, and it forgets every
 *   registered thread the kernel no longer knows (`sys_thread_tid` is 0).
 *   `yield`, `block` and `lock_wait` switch thread-to-thread directly
 *   (`reschedule`); the tick hands its choice back to the kernel
 *   (PREEMPTION). The dispatcher exits when no registered thread
 *   is on a node, which ends the system: a stopped thread (DESTROYING) is
 *   never picked, and only a thread that runs can put it on a node again.
 *
 * PREEMPTION
 *   Every tick wakes the interrupt handler's thread, which `init` created on
 *   `sched_interrupt_entry` (thread.hpp, THE INTERRUPT HANDLER): masked, on
 *   that thread's stack, with the interrupted thread parked. It charges the
 *   slice, picks, and waits again (`sys_trap_wait`) naming the thread to run
 *   next -- or null, and the parked thread carries on. A preempted thread
 *   stays parked until it is switched to
 *   again, by a later tick or by `sys_thread_switch` alike. The handler
 *   stands down while an entry point is mid-update (`s_busy`), and when the
 *   parked thread is not `s_running` (the kernel passes its tid): the
 *   dispatcher, or a thread in `switch_to` that has named the next thread
 *   but not yet switched to it. Those cases catch up at the next tick or on
 *   their own.
 *
 * BLOCKING
 *   `block` marks the caller BLOCKED and picks someone else; a BLOCKED thread
 *   is invisible to `pick` until `wake` makes it READY again, and then runs
 *   when `pick` next chooses it, like any other. `wake` is built to be called
 *   from the interrupt handler: it only flips one record, never picks or
 *   switches, and so needs no `s_busy` protection. The classic lost-wakeup
 *   race -- the event lands after the caller looked and before it blocked --
 *   is closed by `wake_pending`: a wake that finds its target not BLOCKED is
 *   remembered, and `block` consumes it and stays READY. `block` writes
 *   BLOCKED before it reads `wake_pending`, and `wake` tests BLOCKED before
 *   it sets `wake_pending`, so whichever instruction the interrupt lands on,
 *   one of the two sides sees the other.
 *
 *   A `block` with a timeout also records `wake_at_us`; `expire` (run at the
 *   top of every `pick`) makes a BLOCKED thread whose time has come READY by
 *   the same compare-and-swap `wake` uses, so the two cannot both win, and
 *   `next_event` makes an idle CPU stop idling when the earliest one is due.
 *   A thread that keeps the CPU without yielding still gets ticked, and the
 *   tick picks, so a timeout is late by at most a tick.
 *
 *   A thread that waits for a page is blocked the same way, by the interrupt
 *   handler: the kernel wakes it with PAGE_WAIT for a cause (trap.hpp), and
 *   the pager's tid, which it wakes. The pager wakes the thread with
 *   `wake` once the page is in; the timeout, PAGE_WAIT_MAX_US, only covers a
 *   thread the kernel could not note. Should nothing else be able to run,
 *   the thread runs on, faults again, and is blocked again.
 *
 * DEVICE INTERRUPTS
 *   The scheduler owns the PLIC (`init` grants its window to nobody else).
 *   `init` routes each device's source here (`irq_route`) and hands the
 *   `irq_wait` entry it gets back to that device's driver: one entry per
 *   route, so holding it is the right to that source and no other. The
 *   driver's thread sleeps in `irq_wait`. When the external interrupt wakes
 *   the handler, it claims every pending source at the PLIC, marks its
 *   route and wakes its waiter (`claim_and_wake`); nothing else. A claimed
 *   source cannot interrupt again until it is completed, so a
 *   level-triggered device does not storm while its driver gets round to
 *   it: the driver's next `irq_wait` completes it, once the driver has dealt
 *   with the device. A wake that lands before the driver sleeps is not lost:
 *   `irq_wait` looks at the route's `pending` after it has named itself the
 *   waiter, and `block` keeps a wake that comes early (BLOCKING). A source
 *   nobody routed is turned off at the PLIC when it first fires.
 *
 * KILLING
 *   `thread_kill` asks the kernel to end a thread (`sys_thread_kill`, see
 *   unwind.hpp): it ends when it is next back in its own code, inside no
 *   call; a call it is inside runs to its return. The thread only ends once
 *   it runs, so a killed thread never sleeps: `thread_kill` wakes it as
 *   `wake` does, and every later `block` returns SCHED_KILLED at once, so a
 *   callee that was waiting on its behalf returns instead. Its record is forgotten like any exited
 *   thread's (DISPATCH), or, if the kernel tore it down before it ever ran,
 *   on the next refused switch to it. A stopped thread (DESTROYING) is put on
 *   the killer's node first, which pays for it to run to its end. A thread
 *   that is stopped after it was killed, before it has ended, stays stopped
 *   like any other until it is moved or killed again.
 *
 * DESTROYING
 *   `quota_destroy(parent, child)` frees the child and every node under it,
 *   and their bandwidth goes back to `parent`. Their threads stop at once: a
 *   stopped thread keeps its record (with no node), its state and its
 *   registration, and is never picked for itself. `thread_register` puts it
 *   on another node, where it carries on. A node derived with a term
 *   (`guaranteed_until_us`) cannot be destroyed before the term ends, and a
 *   child's guarantee never outlasts its parent's.
 *
 * LOCKS
 *   A lock is a word in the memory of the compartment that uses it (abi.hpp);
 *   taking and releasing one nobody waits for never reaches the scheduler.
 *   `lock_wait` puts the caller to sleep (LOCK_WAIT), recorded as waiting for
 *   the owner. It is still offered to `pick`, and when it is chosen the owner
 *   runs in its place (`runs_for`), following owners that are waiting in
 *   turn: the waiter's node is charged (`paying`), and the owner runs in the
 *   waiter's class. That is how a stopped owner gets out of the way.
 *   `lock_wake` writes the next owner into the word and wakes it: waiters on
 *   a node before stopped ones, then the most urgent class, then the one
 *   waiting longest. A thread that ends holding a lock wakes its waiters,
 *   and the first to try again gets the lock with SCHED_OWNER_DEAD. A wait
 *   that would close a loop of owners is refused with SCHED_DEADLOCK. A
 *   killed thread waits for a lock like any other, and holds it until it
 *   releases it: a kill never cuts a call short (unwind.hpp).
 *
 * IDLE
 *   When nothing can run the CPU idles in the scheduler (`idle_until`): a
 *   spin holding `s_busy`, so the tick stands down and nobody is billed for
 *   idle time, ended by the earliest period reset or timeout, or by a wake.
 *   A thread whose node has spent its budget idles there too when it yields,
 *   blocks or waits, rather than running on borrowed time: spare bandwidth
 *   is not handed out, it is idled. The interrupt handler is the one
 *   exception -- it cannot spin masked -- so a thread that never yields
 *   keeps the CPU when nothing else can run.
 */

#include <signetos/hw/platform.hpp>
#include <signetos/irq.hpp>

#include "runtime.hpp"

namespace signetos::user {
namespace {

// --- What `sched` asks `init` for (user/manifest.hpp) -----------------------
// Every interrupt comes to the scheduler: `init` creates its interrupt
// handler's thread and installs it, and `trap_wait` is how that thread waits.
// The PLIC window is how it tells device interrupts apart (DEVICE
// INTERRUPTS).
// `thread_switch`, `thread_tid` and `thread_kill` are what dispatching and
// killing are made of; `OType::QuotaSched` makes `quota_sched` handles; the
// VM entries fund the per-node pages. `naming.publish` is asked for because
// the scheduler publishes its own entry points as it mints them, rather than
// handing them all back in the handshake. Its VM quota pays for the root
// node's page.
#define SCHED_MANIFEST(X)                              \
  M_QUOTA_VM(X, VM_QUOTA)                              \
  M_OTYPE(X, SEAL_AUTH, ::signetos::OType::QuotaSched) \
  M_SYSCALL(X, SYS_THREAD_SWITCH, thread_switch)       \
  M_SYSCALL(X, SYS_THREAD_TID, thread_tid)             \
  M_SYSCALL(X, SYS_THREAD_KILL, thread_kill)           \
  M_SYSCALL(X, SYS_TRAP_WAIT, trap_wait)               \
  M_SYSCALL(X, SYS_VM_ALLOC, vm_allocate)              \
  M_SYSCALL(X, SYS_VM_DEALLOC, vm_deallocate)          \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)    \
  M_SYSCALL(X, SYS_SENTRY, sentry)                     \
  M_MMIO(X, PLIC_MMIO, "plic")                         \
  M_SERVICE(X, UART_SENTRY, "uart")                    \
  M_SERVICE(X, NAMING_PUBLISH, "naming.publish")
SIGNETOS_MANIFEST(SCHED_MANIFEST, 256 * 1024)

constexpr size_t MAX_THREADS = 128;
constexpr size_t MAX_NODES = 64;

// The most a node may owe into its next periods (BUDGETS): a tick, which is
// as far as one pick can overrun.
constexpr int64_t MAX_DEBT_US = static_cast<int64_t>(irq::TICK_US);

// `time` ticks per microsecond; populated from `SchedInterface::timebase_hz`
// (`/cpus` `timebase-frequency` in the DTB, fallback 10 MHz).
uint64_t s_ticks_per_us = 10;

constexpr uint32_t T_FREE = 0;
constexpr uint32_t T_READY = 1;  // running, or able to run
constexpr uint32_t T_BLOCKED =
    2;  // in `block`; invisible to `pick` until woken
constexpr uint32_t T_LOCK_WAIT = 3;  // in `lock_wait` (LOCKS in the header)

struct QuotaSched;

struct ThreadRec {
  Capability thread;       // sealed OType::Thread with Permit_Load
  QuotaSched* node;        // nullptr once stopped (DESTROYING in the header)
  QuotaSched* paying;      // charged for the current slice (BUDGETS, LOCKS);
                           // nullptr: nobody, as for spare time
  uint64_t tid;            // the kernel's id for it (sys_thread_tid)
  uint64_t last_run_us;    // when `pick` last chose it (ORDERING)
  uint64_t wake_at_us;     // BLOCKED with a timeout: READY again at this time
  uint64_t lock_word;      // LOCK_WAIT: the address of the lock's word
  uint64_t lock_owner;     // LOCK_WAIT: the tid of the thread holding it
  uint64_t lock_since_us;  // LOCK_WAIT: when the wait began
  uint32_t state;
  uint32_t wake_pending;  // a wake arrived while not BLOCKED (BLOCKING)
  bool timed_out;         // the last `block` ended by `expire`
  bool killed;            // `thread_kill` was called: `block` never sleeps it
};

// One node per page.
struct alignas(16) QuotaSched {
  QuotaSched* parent;            // nullptr for the root
  uint32_t budget_us;            // C, per period T
  uint32_t period_us;            // T
  uint32_t delegated_budget_us;  // children's C, normalised to our T
  uint8_t priority_class;
  bool dying;                    // `destroy_subtree` is freeing it
  uint64_t guaranteed_until_us;  // not destroyed before this (DESTROYING)
  int64_t remaining_us;          // left this period; below 0, owed (BUDGETS)
  uint64_t period_start_us;
  uint64_t last_run_us;  // when `pick` last chose one of its threads
  Capability page;       // this page, as returned by sys_vm_allocate
  Capability funding;    // the QuotaVm that paid for it
};
static_assert(sizeof(QuotaSched) <= vm::PAGE_SIZE);

// Scheduler state: funded from the compartment's own image (`.bss`).
Capability s_self_comp = nullptr;
Capability s_seal_auth = nullptr;
Capability s_gate_alloc = nullptr;
Capability s_gate_dealloc = nullptr;
Capability s_gate_switch = nullptr;
Capability s_gate_trap_wait = nullptr;
Capability s_gate_thread_tid = nullptr;
Capability s_gate_thread_kill = nullptr;
Capability s_gate_invoke = nullptr;
Capability s_uart = nullptr;

QuotaSched* s_nodes[MAX_NODES];
size_t s_node_count = 0;

ThreadRec s_threads[MAX_THREADS];
size_t s_registered = 0;

// An entry point is updating scheduler state on the current thread: the tick
// handler must not pick (it would see half-updated state). Cleared across
// `sys_thread_switch`, since the thread that comes back may be anything.
bool s_busy = false;

ThreadRec* s_running = nullptr;  // the thread the scheduler last switched to
uint64_t s_slice_start_us = 0;

// Bumped by every `wake`, from interrupt context; `idle_until` polls it so an
// idle CPU notices a thread becoming runnable before the next period reset.
volatile uint64_t s_wakeups = 0;

inline uint64_t now_us() {
  uint64_t t;
  __asm__ volatile("csrr %0, time" : "=r"(t));
  return t / s_ticks_per_us;
}

// The tick handler can land between any two instructions of an entry point
// and decides what it may touch by `s_busy` (PREEMPTION in the header). The
// barriers keep the compiler from moving the stores the flag guards to the
// other side of it. Single hart: a compiler barrier is all that is needed.
inline void compiler_barrier() { __asm__ volatile("" ::: "memory"); }
inline void busy_begin() {
  s_busy = true;
  compiler_barrier();
}
inline void busy_end() {
  compiler_barrier();
  s_busy = false;
}

// Holds `s_busy` for a scope that never switches threads.
struct BusyScope {
  BusyScope() { busy_begin(); }
  ~BusyScope() { busy_end(); }
};

inline uint32_t sat_sub(uint32_t a, uint64_t b) {
  return (b >= a) ? 0 : static_cast<uint32_t>(a - b);
}

// Bytes addressable from `cap`'s current address to the end of its bounds.
uint64_t room(Capability cap) {
  const uint64_t base = capability_get_base(cap);
  const uint64_t end = base + capability_get_length(cap);
  const uint64_t addr = capability_get_address(cap);
  return (addr < base || addr > end) ? 0 : end - addr;
}

// A request must be writable (we report status through it) and whole.
template <typename T>
T* open_request(Capability arg) {
  if (!capability_is_valid(arg) || sealing::is_sealed(arg) ||
      !capability_has_perms(arg, perms::Load | perms::Store) ||
      room(arg) < sizeof(T)) {
    return nullptr;
  }
  return reinterpret_cast<T*>(arg);
}

// The kernel's id for the thread behind `thread`; 0 once it has ended.
uint64_t thread_tid(Capability thread) {
  using FnThreadTid = decltype(&sys_thread_tid);
  return syscall::call<FnThreadTid>(s_gate_invoke, s_gate_thread_tid, thread);
}

// --- Nodes -------------------------------------------------------------------

// Unseals a quota handle. Returns the node, or nullptr if it is not a live one.
QuotaSched* open_quota(Capability handle) {
  Capability payload = sealing::unseal_with(s_seal_auth, handle);
  if (!capability_is_valid(payload) ||
      capability_get_length(payload) != vm::PAGE_SIZE) {
    return nullptr;
  }
  const uint64_t base = capability_get_base(payload);
  for (size_t i = 0; i < s_node_count; ++i) {
    if (capability_get_base(s_nodes[i]->page) == base) {
      return s_nodes[i];
    }
  }
  return nullptr;
}

// The node's handle: its page, sealed.
Capability seal_node(QuotaSched* n) {
  return sealing::seal_with(s_seal_auth,
                            capability_and_perms(n->page, perms::Load));
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

// Whether `n` is `top` or a node under it.
bool within(const QuotaSched* n, const QuotaSched* top) {
  for (; n != nullptr; n = n->parent) {
    if (n == top) {
      return true;
    }
  }
  return false;
}

// Starts the periods that have ended since the node's current one began
// (BUDGETS): each gives the budget back, less what is owed, and budget left
// unused does not pile up.
void replenish(QuotaSched* n, uint64_t now) {
  const uint64_t periods = (now - n->period_start_us) / n->period_us;
  if (periods == 0) {
    return;
  }
  n->period_start_us += periods * n->period_us;
  const int64_t budget = own_budget(n);
  const int64_t refilled =
      n->remaining_us + static_cast<int64_t>(periods) * budget;
  n->remaining_us = refilled < budget ? refilled : budget;
}

// Until when a node derived at `now` with `term_us` (SchedDeriveRequest) may
// not be taken back.
uint64_t guaranteed_until(uint64_t now, uint64_t term_us) {
  if (term_us == init::SCHED_REVOCABLE || term_us == init::SCHED_PERMANENT) {
    return term_us;
  }
  return term_us < init::SCHED_PERMANENT - now ? now + term_us
                                               : init::SCHED_PERMANENT - 1;
}

// A new node under `parent` (nullptr for the root), its page paid for by
// `funding`, with its whole budget for a first period starting now. nullptr
// if the table is full or `funding` cannot pay.
QuotaSched* alloc_node(Capability funding, QuotaSched* parent,
                       uint32_t budget_us, uint32_t period_us,
                       uint8_t priority_class, uint64_t guaranteed_until_us) {
  if (s_node_count >= MAX_NODES) {
    return nullptr;
  }
  using FnAlloc = decltype(&sys_vm_allocate);
  Capability page =
      syscall::call<FnAlloc>(s_gate_invoke, s_gate_alloc, s_self_comp, funding,
                             vm::PAGE_SIZE, 0);
  if (!capability_is_valid(page)) {
    return nullptr;
  }
  QuotaSched* n = reinterpret_cast<QuotaSched*>(page);
  n->parent = parent;
  n->budget_us = budget_us;
  n->period_us = period_us;
  n->priority_class = priority_class;
  n->guaranteed_until_us = guaranteed_until_us;
  n->remaining_us = budget_us;
  n->period_start_us = now_us();
  n->page = page;
  n->funding = funding;
  s_nodes[s_node_count++] = n;
  return n;
}

// Takes `n` out of the table and gives its page back. Nothing may point at it
// any more.
void free_node(QuotaSched* n) {
  for (size_t i = 0; i < s_node_count; ++i) {
    if (s_nodes[i] == n) {
      s_node_count -= 1;
      s_nodes[i] = s_nodes[s_node_count];
      s_nodes[s_node_count] = nullptr;
      break;
    }
  }
  Capability page = n->page;
  Capability funding = n->funding;
  // The page is quarantined by the kernel, not reused; scrub what we can.
  n->page = nullptr;
  n->funding = nullptr;
  using FnDealloc = decltype(&sys_vm_deallocate);
  syscall::call<FnDealloc>(s_gate_invoke, s_gate_dealloc, s_self_comp, funding,
                           page);
}

// Frees `top` and every node under it. `top`'s bandwidth goes back to its
// parent; theirs was part of it. Their threads stop (DESTROYING).
void destroy_subtree(QuotaSched* top) {
  QuotaSched* parent = top->parent;
  parent->delegated_budget_us = sat_sub(
      parent->delegated_budget_us,
      normalised_share(top->budget_us, top->period_us, parent->period_us));
  // Marked first: `within` walks up through parents, which must still be
  // there when it does.
  for (size_t i = 0; i < s_node_count; ++i) {
    s_nodes[i]->dying = within(s_nodes[i], top);
  }
  for (ThreadRec& t : s_threads) {
    if (t.node != nullptr && t.node->dying) {
      t.node = nullptr;
    }
    if (t.paying != nullptr && t.paying->dying) {
      t.paying = nullptr;
    }
  }
  for (size_t i = 0; i < s_node_count;) {
    if (s_nodes[i]->dying) {
      free_node(s_nodes[i]);  // moves the last node into slot `i`
    } else {
      ++i;
    }
  }
}

// --- Threads -----------------------------------------------------------------

// A thread's `tid` is the kernel's id for it (`sys_thread_tid`), fetched at
// registration; the scheduler has no numbering of its own.
ThreadRec* find_registered(uint64_t tid) {
  for (ThreadRec& t : s_threads) {
    if (t.state != T_FREE && t.tid == tid) {
      return &t;
    }
  }
  return nullptr;
}

// The calling thread's record: `s_running`, if that is the thread running
// (`utidc`, which only the kernel writes). nullptr from anything the
// scheduler does not run -- `init`, the dispatcher -- and from a thread in
// `switch_to` that has named the next thread but not yet switched to it.
ThreadRec* caller() {
  ThreadRec* t = s_running;
  return t != nullptr && t->tid == self_tid() ? t : nullptr;
}

// Bills the slice that ends now to whoever pays for the running thread
// (BUDGETS, LOCKS), and starts the next.
void charge_running(uint64_t now) {
  const int64_t used = static_cast<int64_t>(now - s_slice_start_us);
  s_slice_start_us = now;
  QuotaSched* n = s_running != nullptr ? s_running->paying : nullptr;
  if (n != nullptr) {
    const int64_t left = n->remaining_us - used;
    n->remaining_us = left > -MAX_DEBT_US ? left : -MAX_DEBT_US;
  }
}

// What runs when `t` is chosen: `t` itself if it is ready; if it is waiting
// for a lock, the lock's owner, following owners that are waiting in turn
// (LOCKS in the header). nullptr if that ends at a thread that cannot run.
ThreadRec* runs_for(ThreadRec* t) {
  for (size_t hops = 0; t != nullptr && hops < MAX_THREADS; ++hops) {
    if (t->state == T_READY) {
      return t;
    }
    if (t->state != T_LOCK_WAIT) {
      return nullptr;
    }
    t = find_registered(t->lock_owner);
  }
  return nullptr;
}

// Whether `pick` prefers `a` to `b` (ORDERING): the more urgent class, then
// the node served longer ago, then the thread chosen longer ago.
bool chosen_before(const ThreadRec* a, const ThreadRec* b) {
  const QuotaSched* na = a->node;
  const QuotaSched* nb = b->node;
  if (na->priority_class != nb->priority_class) {
    return na->priority_class < nb->priority_class;
  }
  if (na->last_run_us != nb->last_run_us) {
    return na->last_run_us < nb->last_run_us;
  }
  return a->last_run_us < b->last_run_us;
}

// Makes every BLOCKED thread whose timeout has passed READY again (BLOCKING
// in the header). The compare-and-swap is the one `wake` uses: whichever of
// the two gets there first, the other finds the thread no longer BLOCKED.
void expire(uint64_t now) {
  for (ThreadRec& t : s_threads) {
    if (t.wake_at_us == 0 || t.wake_at_us > now) {
      continue;
    }
    uint32_t expected = T_BLOCKED;
    if (__atomic_compare_exchange_n(&t.state, &expected, T_READY, false,
                                    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
      t.timed_out = true;
    }
    t.wake_at_us = 0;
  }
}

// Chooses what runs next (ORDERING), or nullptr if nothing can. Whatever runs
// is charged to the chosen thread's node: its own, or, for a lock's owner
// running in a waiter's place, the waiter's (LOCKS).
ThreadRec* pick(uint64_t now) {
  expire(now);
  ThreadRec* chosen = nullptr;
  ThreadRec* run = nullptr;
  for (ThreadRec& t : s_threads) {
    if (t.state == T_FREE || t.node == nullptr) {
      continue;
    }
    replenish(t.node, now);
    if (t.node->remaining_us <= 0) {
      continue;
    }
    ThreadRec* r = runs_for(&t);
    if (r != nullptr && (chosen == nullptr || chosen_before(&t, chosen))) {
      chosen = &t;
      run = r;
    }
  }
  if (chosen == nullptr) {
    return nullptr;
  }
  chosen->last_run_us = now;
  chosen->node->last_run_us = now;
  run->paying = chosen->node;
  return run;
}

// When an idle CPU next has something to look at (IDLE): the earliest
// timeout of a blocked thread, or the earliest period reset of a node one of
// whose threads could run but for its budget. `~0` if neither.
uint64_t next_event(uint64_t now) {
  uint64_t at = ~0ULL;
  for (ThreadRec& t : s_threads) {
    uint64_t when = ~0ULL;
    if (t.state == T_BLOCKED && t.wake_at_us != 0) {
      when = t.wake_at_us;
    } else if (t.state != T_FREE && t.node != nullptr &&
               runs_for(&t) != nullptr) {
      when = t.node->period_start_us + t.node->period_us;
    }
    at = when < at ? when : at;
  }
  return at < now ? now : at;
}

// Forgets `t`, which has ended. Threads waiting for a lock it held try again;
// the first gets the lock, with SCHED_OWNER_DEAD (LOCKS).
void reap(ThreadRec* t) {
  for (ThreadRec& w : s_threads) {
    if (w.state == T_LOCK_WAIT && w.lock_owner == t->tid) {
      w.state = T_READY;
    }
  }
  if (s_running == t) {
    s_running = nullptr;
  }
  t->thread = nullptr;
  t->node = nullptr;
  t->paying = nullptr;
  __atomic_store_n(&t->state, T_FREE, __ATOMIC_SEQ_CST);
  s_registered -= 1;
}

// True if some registered thread is on a node, so something can still run
// (DISPATCH).
bool any_on_node() {
  for (const ThreadRec& t : s_threads) {
    if (t.state != T_FREE && t.node != nullptr) {
      return true;
    }
  }
  return false;
}

// Forgets every registered thread the kernel no longer knows: the one that
// has just exited, and any that was killed before it ever ran (DISPATCH).
void reap_ended() {
  for (ThreadRec& t : s_threads) {
    if (t.state != T_FREE && thread_tid(t.thread) == 0) {
      reap(&t);
    }
  }
}

// Hands the CPU to `t`. True once something switches back to the caller,
// which then runs on with `s_busy` clear: whoever switched to it cleared it.
// False if the kernel refused, which it does only for a thread that has
// ended (nothing here switches to the running one): `t` is reaped, nothing
// ran, and the caller still holds `s_busy`, `s_running` and its slice as
// before. `s_running` names `t` before the switch, so a tick landing in
// between finds that the interrupted thread is not `s_running` and stands
// down (PREEMPTION in the header).
bool switch_to(ThreadRec* t, uint64_t now) {
  ThreadRec* const prev = s_running;
  s_running = t;
  s_slice_start_us = now;
  busy_end();
  using FnSwitch = decltype(&sys_thread_switch);
  if (syscall::call<FnSwitch>(s_gate_invoke, s_gate_switch, t->thread) == 0) {
    return true;
  }
  busy_begin();
  s_running = prev;
  reap(t);
  return false;
}

// Spins until `at` or a wake, whichever is first, and returns the time
// afterwards (IDLE in the header). Called holding `s_busy`, which keeps the
// tick out; ticks and device interrupts are still taken, which is how a wake
// gets in. The idle time is billed to nobody. `wfi` would do here instead of
// a spin -- everything runs in M-mode -- but a spin keeps the time base
// simple.
uint64_t idle_until(uint64_t at) {
  const uint64_t seen = s_wakeups;
  while (now_us() < at && s_wakeups == seen) {
  }
  const uint64_t now = now_us();
  s_slice_start_us = now;
  return now;
}

// Runs whatever `pick` chooses until it chooses `cur`, the calling thread,
// again. Called holding `s_busy`, with `cur`'s slice charged and its state
// set: READY to stay in the running, BLOCKED or LOCK_WAIT to sleep. Returns
// with `s_busy` clear and `cur` running. When nothing can run it idles (IDLE
// in the header).
void reschedule(ThreadRec* cur, uint64_t now) {
  for (;;) {
    ThreadRec* next = pick(now);
    if (next == cur) {
      busy_end();
      return;
    }
    if (next == nullptr) {
      now = idle_until(next_event(now));
    } else if (switch_to(next, now)) {
      return;
    }
    // Otherwise `next` had ended and is reaped: pick again.
  }
}

// The lock word `word` points at, or nullptr: it must be an unsealed
// Load capability to eight aligned bytes. The scheduler only reads it.
const uint64_t* open_lock_word(Capability word) {
  if (!capability_is_valid(word) || sealing::is_sealed(word) ||
      !capability_has_perms(word, perms::Load)) {
    return nullptr;
  }
  const uint64_t addr = capability_get_address(word);
  const uint64_t base = capability_get_base(word);
  if (addr % sizeof(uint64_t) != 0 || addr < base ||
      addr + sizeof(uint64_t) > base + capability_get_length(word)) {
    return nullptr;
  }
  return reinterpret_cast<const uint64_t*>(word);
}

// Whether `t` is `target`, or is waiting for it through a chain of lock
// owners.
bool waits_on(ThreadRec* t, const ThreadRec* target) {
  for (size_t hops = 0; t != nullptr && hops < MAX_THREADS; ++hops) {
    if (t == target) {
      return true;
    }
    if (t->state != T_LOCK_WAIT) {
      return false;
    }
    t = find_registered(t->lock_owner);
  }
  return false;
}

// Which of two waiters gets a lock first: one on a node before a stopped one,
// then the more urgent class, then the one that has waited longer.
bool goes_first(const ThreadRec* a, const ThreadRec* b) {
  if ((a->node != nullptr) != (b->node != nullptr)) {
    return a->node != nullptr;
  }
  if (a->node != nullptr &&
      a->node->priority_class != b->node->priority_class) {
    return a->node->priority_class < b->node->priority_class;
  }
  return a->lock_since_us < b->lock_since_us;
}

// Makes `to` the owner of the lock at `addr` in the waiter records: points
// remaining waiters at `to` and marks `to` as holding the lock in flight.
// The lock word itself is updated by the caller's compartment (runtime.hpp).
void set_owner(uint64_t addr, ThreadRec* to) {
  for (ThreadRec& w : s_threads) {
    if (&w != to && w.state == T_LOCK_WAIT && w.lock_word == addr) {
      w.lock_owner = to->tid;
    }
  }
  to->lock_owner = to->tid;
}

}  // namespace

SIGNETOS_DEFAULT_FAULT_HANDLER("sched")

// --- Entry points --------------------------------------------------------------

extern "C" int64_t sched_quota_derive_entry(Capability arg) {
  auto* req = open_request<init::SchedDeriveRequest>(arg);
  if (req == nullptr) {
    return init::SCHED_BAD_REQUEST;
  }
  BusyScope busy;
  req->out_quota = nullptr;
  auto done = [&](int64_t status) {
    req->status = status;
    return status;
  };
  QuotaSched* parent = open_quota(req->parent);
  if (parent == nullptr) {
    return done(init::SCHED_INVALID_QUOTA);
  }
  if (req->budget_us == 0 || req->period_us == 0 ||
      req->budget_us > req->period_us ||
      req->priority_class > init::PRIORITY_BATCH ||
      !sealing::is_sealed_as(OType::QuotaVm, req->node_funding)) {
    return done(init::SCHED_BAD_REQUEST);
  }
  // No more urgent than the parent, and guaranteed for no longer.
  const uint64_t until = guaranteed_until(now_us(), req->term_us);
  if (req->priority_class < parent->priority_class ||
      until > parent->guaranteed_until_us) {
    return done(init::SCHED_PERMISSION);
  }
  // Temporal conservation: C_c / T_c <= (C_p - D_p) / T_p.
  if (static_cast<uint64_t>(req->budget_us) * parent->period_us >
      static_cast<uint64_t>(own_budget(parent)) * req->period_us) {
    return done(init::SCHED_BANDWIDTH);
  }
  QuotaSched* n = alloc_node(req->node_funding, parent, req->budget_us,
                             req->period_us, req->priority_class, until);
  Capability handle = n != nullptr ? seal_node(n) : nullptr;
  if (!capability_is_valid(handle)) {
    if (n != nullptr) {
      free_node(n);
    }
    return done(init::SCHED_NO_MEMORY);
  }
  parent->delegated_budget_us += static_cast<uint32_t>(
      normalised_share(req->budget_us, req->period_us, parent->period_us));
  // The parent's own threads just lost bandwidth; cap what is left.
  if (parent->remaining_us > own_budget(parent)) {
    parent->remaining_us = own_budget(parent);
  }
  req->out_quota = handle;
  return done(init::SCHED_OK);
}

extern "C" int64_t sched_yield_entry();

// Takes back the time `parent` gave `child` (DESTROYING in the header).
extern "C" int64_t sched_quota_destroy_entry(Capability parent,
                                             Capability child) {
  {
    BusyScope busy;
    QuotaSched* p = open_quota(parent);
    QuotaSched* c = open_quota(child);
    if (p == nullptr || c == nullptr) {
      return init::SCHED_INVALID_QUOTA;
    }
    if (c->parent != p) {
      return init::SCHED_PERMISSION;
    }
    if (c->guaranteed_until_us > now_us()) {
      return init::SCHED_BUSY;
    }
    destroy_subtree(c);
  }
  // The caller was on one of those nodes: it stops here.
  const ThreadRec* me = caller();
  if (me != nullptr && me->node == nullptr) {
    sched_yield_entry();
  }
  return init::SCHED_OK;
}

extern "C" int64_t sched_quota_query_entry(Capability quota, Capability arg) {
  auto* req = open_request<init::SchedQueryRequest>(arg);
  if (req == nullptr) {
    return init::SCHED_BAD_REQUEST;
  }
  BusyScope busy;
  QuotaSched* n = open_quota(quota);
  if (n == nullptr) {
    req->status = init::SCHED_INVALID_QUOTA;
    return req->status;
  }
  uint32_t threads = 0;
  for (const ThreadRec& t : s_threads) {
    if (t.state != T_FREE && within(t.node, n)) {
      threads += 1;
    }
  }
  uint32_t children = 0;
  for (size_t i = 0; i < s_node_count; ++i) {
    if (s_nodes[i]->parent == n) {
      children += 1;
    }
  }
  req->guaranteed_until_us = n->guaranteed_until_us;
  req->budget_us = n->budget_us;
  req->period_us = n->period_us;
  req->threads = threads;
  req->children = children;
  req->priority_class = n->priority_class;
  req->status = init::SCHED_OK;
  return req->status;
}

extern "C" int64_t sched_thread_register_entry(Capability thread,
                                               Capability quota) {
  BusyScope busy;
  QuotaSched* n = open_quota(quota);
  if (n == nullptr) {
    return init::SCHED_INVALID_QUOTA;
  }
  if (!sealing::is_sealed_as(OType::Thread, thread) ||
      (capability_get_perms(thread) & perms::Load) == 0) {
    return init::SCHED_INVALID_THREAD;
  }
  // The thread's name is the kernel's id for it, fetched through the handle
  // we were handed rather than supplied by the caller, so nobody can file a
  // thread under another's number. 0: the kernel does not know this handle
  // as a live thread (stale, or forged).
  const uint64_t tid = thread_tid(thread);
  if (tid == 0) {
    return init::SCHED_INVALID_THREAD;
  }
  // A stopped thread goes onto `n` and carries on from where it stopped.
  ThreadRec* rec = find_registered(tid);
  if (rec != nullptr) {
    if (rec->node != nullptr) {
      return init::SCHED_INVALID_THREAD;  // it is on a node already
    }
    rec->node = n;
    return static_cast<int64_t>(tid);
  }
  for (ThreadRec& t : s_threads) {
    if (t.state == T_FREE) {
      rec = &t;
      break;
    }
  }
  if (rec == nullptr) {
    return init::SCHED_FULL;
  }
  *rec = ThreadRec{};
  rec->thread = thread;
  rec->node = n;
  rec->tid = tid;
  // Filled in before `wake`, from interrupt context, can find it.
  compiler_barrier();
  __atomic_store_n(&rec->state, T_READY, __ATOMIC_SEQ_CST);
  s_registered += 1;
  return static_cast<int64_t>(tid);
}

// Called in the yielding thread's own context (through the domain switcher).
extern "C" int64_t sched_yield_entry() {
  ThreadRec* cur = caller();
  if (cur == nullptr) {
    return 0;
  }
  busy_begin();
  const uint64_t now = now_us();
  charge_running(now);
  reschedule(cur, now);
  return 0;
}

// Called in the blocking thread's own context. Returns once the thread has
// been woken, by a `wake` that was already pending or one that made it
// READY again, or `timeout_us` ran out first, and `pick` has chosen it. See
// BLOCKING in the header. `timeout_us == 0` blocks without a timeout.
extern "C" int64_t sched_block_entry(uint64_t timeout_us) {
  ThreadRec* cur = caller();
  if (cur == nullptr) {
    return init::SCHED_INVALID_THREAD;
  }
  if (__atomic_load_n(&cur->killed, __ATOMIC_SEQ_CST)) {
    return init::SCHED_KILLED;  // a killed thread never sleeps
  }
  busy_begin();
  const uint64_t now = now_us();
  charge_running(now);
  cur->timed_out = false;
  cur->wake_at_us = 0;
  if (timeout_us != 0) {
    const uint64_t at = now + timeout_us;
    cur->wake_at_us = at < now ? ~0ULL : at;
  }
  // BLOCKED must be visible before we look at `wake_pending`: a wake landing
  // after this store makes us READY itself, and one that landed before it
  // left the pending flag.
  __atomic_store_n(&cur->state, T_BLOCKED, __ATOMIC_SEQ_CST);
  if (__atomic_exchange_n(&cur->wake_pending, 0u, __ATOMIC_SEQ_CST) != 0) {
    __atomic_store_n(&cur->state, T_READY, __ATOMIC_SEQ_CST);
  }
  reschedule(cur, now);
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
    // Not blocked (READY, or about to block): remember the wake so the next
    // `block` returns instead of sleeping through it.
    __atomic_store_n(&t->wake_pending, 1u, __ATOMIC_SEQ_CST);
  }
  s_wakeups = s_wakeups + 1;  // ends any `idle_until` in progress
  return init::SCHED_OK;
}

// Ends the thread behind `thread` (needs Store) through `sys_thread_kill`,
// then wakes it so it runs to where the kernel ends it (KILLING above). A
// stopped thread is put on the caller's node first, so unlike `wake` this is
// for thread context only.
extern "C" int64_t sched_thread_kill_entry(Capability thread) {
  if (!sealing::is_sealed_as(OType::Thread, thread)) {
    return init::SCHED_INVALID_THREAD;
  }
  // The id first: a thread that never ran is torn down by the kill.
  const uint64_t tid = thread_tid(thread);
  using FnThreadKill = decltype(&sys_thread_kill);
  const uint64_t st =
      syscall::call<FnThreadKill>(s_gate_invoke, s_gate_thread_kill, thread);
  if (st != static_cast<uint64_t>(Status::Ok)) {
    return st == static_cast<uint64_t>(Status::InsufficientPermission)
               ? init::SCHED_PERMISSION
               : init::SCHED_INVALID_THREAD;
  }
  BusyScope busy;
  ThreadRec* t = tid != 0 ? find_registered(tid) : nullptr;
  if (t == nullptr) {
    return init::SCHED_OK;  // not registered with us
  }
  const ThreadRec* me = caller();
  if (t->node == nullptr && me != nullptr) {
    t->node = me->node;
  }
  // `killed` is set before the wake. A full `wake` is needed, not just the
  // BLOCKED -> READY flip: a kill can land between `block`'s test of
  // `killed` and the thread going to sleep (it may be preempted there), and
  // only `wake_pending` makes that sleep return at once.
  __atomic_store_n(&t->killed, true, __ATOMIC_SEQ_CST);
  sched_wake_entry(tid);
  return init::SCHED_OK;
}

// Called by a thread that found the lock at `word` taken, with the value it
// saw there, LOCK_WAITERS set. Sleeps until the lock is handed to it (LOCKS
// in the header), returning its own tid (> 0) once granted, SCHED_OWNER_DEAD
// if the owner ended holding it, or SCHED_OK (0) if the word changed before
// the sleep so the caller looks again.
extern "C" int64_t sched_lock_wait_entry(Capability word_cap, uint64_t seen) {
  ThreadRec* cur = caller();
  if (cur == nullptr) {
    return init::SCHED_INVALID_THREAD;
  }
  const uint64_t* word = open_lock_word(word_cap);
  if (word == nullptr) {
    return init::SCHED_BAD_REQUEST;
  }
  const uint64_t addr = capability_get_address(word_cap);
  busy_begin();
  int64_t status = init::SCHED_OK;
  ThreadRec* owner = nullptr;
  if ((seen & init::LOCK_WAITERS) == 0 ||
      __atomic_load_n(word, __ATOMIC_SEQ_CST) != seen) {
    // It changed meanwhile: the caller looks again.
  } else {
    owner = find_registered(seen & ~init::LOCK_WAITERS);
    for (ThreadRec& w : s_threads) {
      if (w.state == T_READY && w.lock_word == addr && w.lock_owner == w.tid) {
        owner = &w;  // handoff in flight to `w`
        break;
      }
    }
    if (owner == nullptr) {
      set_owner(addr, cur);  // it ended holding the lock
      cur->lock_owner = 0;
      status = init::SCHED_OWNER_DEAD;
    } else if (waits_on(owner, cur)) {
      status = init::SCHED_DEADLOCK;
    } else {
      const uint64_t now = now_us();
      charge_running(now);
      cur->lock_word = addr;
      cur->lock_owner = owner->tid;
      cur->lock_since_us = now;
      cur->state = T_LOCK_WAIT;
      reschedule(cur, now);  // until the lock is handed to us
      const bool granted = (cur->lock_owner == cur->tid);
      cur->lock_word = 0;
      cur->lock_owner = 0;
      return granted ? static_cast<int64_t>(cur->tid) : init::SCHED_OK;
    }
  }
  busy_end();
  return status;
}

// Called by the owner of the lock at `word` as it releases it, having seen
// LOCK_WAITERS: wakes the waiter that goes first and returns its tid (> 0) for
// the caller to write into `word`, or 0 (SCHED_OK) if nobody is waiting.
extern "C" int64_t sched_lock_wake_entry(Capability word_cap) {
  ThreadRec* cur = caller();
  if (cur == nullptr) {
    return init::SCHED_INVALID_THREAD;
  }
  const uint64_t* word = open_lock_word(word_cap);
  if (word == nullptr) {
    return init::SCHED_BAD_REQUEST;
  }
  BusyScope busy;
  if ((__atomic_load_n(word, __ATOMIC_SEQ_CST) & ~init::LOCK_WAITERS) !=
      cur->tid) {
    return init::SCHED_PERMISSION;  // not the owner
  }
  const uint64_t addr = capability_get_address(word_cap);
  ThreadRec* next = nullptr;
  for (ThreadRec& w : s_threads) {
    if (w.state == T_LOCK_WAIT && w.lock_word == addr &&
        (next == nullptr || goes_first(&w, next))) {
      next = &w;
    }
  }
  if (next == nullptr) {
    return init::SCHED_OK;
  }
  set_owner(addr, next);
  next->state = T_READY;
  return static_cast<int64_t>(next->tid);
}

// --- Device interrupts (DEVICE INTERRUPTS in the header) -----------------------

namespace {

// One per routed PLIC source. The interrupt handler sets `claimed` and
// `pending` and reads `waiter`; the route's `irq_wait` does the opposite.
// Each is one aligned word, so either side can land between any two
// instructions of the other.
struct Route {
  uint32_t source;   // 0: free
  uint32_t pending;  // it fired since the waiter last looked
  uint32_t claimed;  // claimed at the PLIC, not completed yet
  uint32_t pad_;
  uint64_t waiter;   // the tid asleep in `irq_wait`; 0: none
};
constexpr size_t MAX_ROUTES = 4;
Route s_routes[MAX_ROUTES];

Capability s_plic = nullptr;  // the PLIC window (Load|Store); null: unusable
uint64_t s_plic_context = 0;  // this hart's M-mode context
uint32_t s_plic_ndev = platform::DEFAULT_PLIC_NDEV;

// 32-bit PLIC registers, offsets from platform.hpp.
volatile uint32_t* plic_reg(uint64_t offset) {
  return reinterpret_cast<volatile uint32_t*>(
      capability_set_address(s_plic, capability_get_base(s_plic) + offset));
}

volatile uint32_t* plic_enable_word(uint32_t source) {
  return plic_reg(platform::PLIC_ENABLE_BASE +
                  s_plic_context * platform::PLIC_ENABLE_STRIDE +
                  4 * (source / 32));
}

// Read: claims the highest-priority pending source (0: none). Write a
// claimed source back: completes it, and it may interrupt again.
volatile uint32_t* plic_claim() {
  return plic_reg(platform::PLIC_CONTEXT_BASE +
                  s_plic_context * platform::PLIC_CONTEXT_STRIDE +
                  platform::PLIC_CLAIM_OFFSET);
}

// The external interrupt, in the interrupt handler: claims every source the
// PLIC has pending for this hart, marks its route and wakes its waiter. A
// routed source stays claimed until its driver's next `irq_wait`; one nobody
// routed is turned off rather than left to storm.
void claim_and_wake() {
  if (!capability_is_valid(s_plic)) {
    return;
  }
  volatile uint32_t* claim = plic_claim();
  for (uint32_t source = *claim; source != 0; source = *claim) {
    Route* r = nullptr;
    for (Route& x : s_routes) {
      r = x.source == source ? &x : r;
    }
    if (r == nullptr) {
      volatile uint32_t* word = plic_enable_word(source);
      *word = *word & ~(1u << (source % 32));
      *claim = source;
      continue;
    }
    __atomic_store_n(&r->claimed, 1u, __ATOMIC_SEQ_CST);
    __atomic_store_n(&r->pending, 1u, __ATOMIC_SEQ_CST);
    const uint64_t waiter = __atomic_load_n(&r->waiter, __ATOMIC_SEQ_CST);
    if (waiter != 0) {
      sched_wake_entry(waiter);
    }
  }
}

// `sched.irq_wait` for route N (abi.hpp): completes the source's last
// interrupt, then sleeps until the next one, or `timeout_us` (0: none). An
// entry point carries nothing of its own, so the route it is for is which of
// these functions it enters.
template <size_t N>
int64_t sched_irq_wait_entry(uint64_t timeout_us) {
  Route& r = s_routes[N];
  ThreadRec* cur = caller();
  if (cur == nullptr) {
    return init::SCHED_INVALID_THREAD;
  }
  uint64_t nobody = 0;
  if (!__atomic_compare_exchange_n(&r.waiter, &nobody, cur->tid, false,
                                   __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
    return init::SCHED_BUSY;
  }
  if (__atomic_exchange_n(&r.claimed, 0u, __ATOMIC_SEQ_CST) != 0) {
    *plic_claim() = r.source;
  }
  // Named the waiter before looking: an interrupt from here on wakes us, and
  // `block` keeps a wake that lands before it sleeps (BLOCKING).
  int64_t status = init::SCHED_OK;
  while (status == init::SCHED_OK &&
         __atomic_exchange_n(&r.pending, 0u, __ATOMIC_SEQ_CST) == 0) {
    status = sched_block_entry(timeout_us);
  }
  __atomic_store_n(&r.waiter, 0, __ATOMIC_SEQ_CST);
  return status;
}

const void* irq_wait_fn(size_t n) {
  static_assert(MAX_ROUTES == 4);
  switch (n) {
    case 0: return reinterpret_cast<const void*>(&sched_irq_wait_entry<0>);
    case 1: return reinterpret_cast<const void*>(&sched_irq_wait_entry<1>);
    case 2: return reinterpret_cast<const void*>(&sched_irq_wait_entry<2>);
    default: return reinterpret_cast<const void*>(&sched_irq_wait_entry<3>);
  }
}

}  // namespace

// `sched.irq_route` (abi.hpp): routes PLIC source `source` and returns its
// `irq_wait` entry for `init` to hand to the device's driver; null if there
// is no PLIC, the source is out of range or routed already, or no route is
// left. It goes back to `init` through `SchedInterface` and is not
// published: which device reaches which driver is `init`'s decision.
extern "C" Capability sched_irq_route_entry(uint64_t source) {
  if (!capability_is_valid(s_plic) || source == 0 || source > s_plic_ndev) {
    return nullptr;
  }
  size_t n = MAX_ROUTES;
  for (size_t i = MAX_ROUTES; i-- > 0;) {
    if (s_routes[i].source == source) {
      return nullptr;
    }
    n = s_routes[i].source == 0 ? i : n;
  }
  const Capability wait =
      n == MAX_ROUTES ? nullptr
                      : mint_entry(s_gate_invoke, rw_table()[SLOT_SYS_SENTRY],
                                   s_self_comp, irq_wait_fn(n));
  if (!sealing::is_sealed_as(OType::EntryPoint, wait)) {
    return nullptr;
  }
  // The route is in place before the source can fire.
  s_routes[n].source = static_cast<uint32_t>(source);
  *plic_reg(platform::PLIC_PRIORITY + 4 * source) = 1;  // lowest non-zero
  volatile uint32_t* word = plic_enable_word(static_cast<uint32_t>(source));
  *word = *word | (1u << (source % 32));
  return wait;
}

// The longest a thread waiting for a page sleeps before it tries again
// (BLOCKING).
constexpr uint64_t PAGE_WAIT_MAX_US = 10'000;

// One interrupt (irq::Event), in the interrupt handler's thread: the thread
// to run next, or null to carry on with the interrupted one. A device
// interrupt only wakes its driver (DEVICE INTERRUPTS); the tick picks
// (PREEMPTION); with PAGE_WAIT for the cause, the interrupted thread waits
// for a page (BLOCKING).
Capability on_interrupt(uint64_t cause, uint64_t tid, uint64_t pager) {
  if (cause == irq::IRQ_M_EXT) {
    claim_and_wake();
    return nullptr;
  }
  // Nothing to do while scheduler state is mid-update on the parked thread,
  // or if that thread is not `s_running`.
  ThreadRec* cur = s_running;
  if (s_busy || cur == nullptr || cur->tid != tid) {
    return nullptr;
  }
  busy_begin();
  const uint64_t now = now_us();
  charge_running(now);
  const bool page_wait = cause == irq::PAGE_WAIT &&
                         !__atomic_load_n(&cur->killed, __ATOMIC_SEQ_CST);
  if (page_wait) {
    if (pager != 0) {
      sched_wake_entry(pager);
    }
    cur->timed_out = false;
    cur->wake_at_us = now + PAGE_WAIT_MAX_US;
    __atomic_store_n(&cur->state, T_BLOCKED, __ATOMIC_SEQ_CST);
  }
  for (;;) {
    ThreadRec* next = pick(now);
    if (next != nullptr && next != cur && thread_tid(next->thread) == 0) {
      reap(next);  // it has ended: pick again
      continue;
    }
    if (next == nullptr || next == cur) {
      if (next == nullptr) {
        // Nothing else can run, and a handler cannot idle (IDLE): `cur` runs
        // on, on spare time, billed to nobody (BUDGETS). One waiting for a
        // page faults again and is back here.
        cur->paying = nullptr;
        if (page_wait) {
          uint32_t expected = T_BLOCKED;
          __atomic_compare_exchange_n(&cur->state, &expected, T_READY, false,
                                      __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
          cur->wake_at_us = 0;
        }
      }
      busy_end();
      return nullptr;
    }
    // Someone else should run: the handler's wait resumes it, and `cur`
    // stays parked until it is switched to again.
    s_running = next;
    s_slice_start_us = now;
    busy_end();
    return next->thread;
  }
}

// The interrupt handler's thread (irq.hpp; thread.hpp, THE INTERRUPT
// HANDLER), which `init` creates on this entry and installs. It runs masked,
// on its own stack, and spends its life waiting in `sys_trap_wait`, which
// runs the thread it names and returns at the next interrupt. The interrupt
// that starts it is not reported, so its first wait names nobody.
extern "C" void sched_interrupt_entry(Capability arg) {
  (void)arg;
  irq::Event ev{};
  Capability next = nullptr;
  using FnWait = decltype(&sys_trap_wait);
  while (syscall::call<FnWait>(s_gate_invoke, s_gate_trap_wait, next,
                               reinterpret_cast<Capability>(&ev)) == 0) {
    next = on_interrupt(ev.cause, ev.tid, ev.aux);
  }
}

// The dispatcher thread (`sched.run`), created and re-dispatched by the kernel.
extern "C" uint64_t sched_run_entry(Capability arg) {
  (void)arg;
  print(s_gate_invoke, s_uart, "[sched]    Dispatcher running\n");
  for (;;) {
    busy_begin();
    const uint64_t now = now_us();
    // Here at the start, and each time a thread has exited: its last slice
    // is billed, and every thread that has ended is forgotten.
    charge_running(now);
    s_running = nullptr;
    reap_ended();
    if (!any_on_node()) {
      break;
    }
    ThreadRec* t = pick(now);
    if (t == nullptr) {
      // Every thread that could run is on a node out of budget, or
      // everything is asleep: idle until a period reset, a timeout or a wake.
      idle_until(next_event(now));
    } else {
      switch_to(t, now);  // back once a thread exits, or at once if `t` had
    }
  }
  busy_end();
  print(s_gate_invoke, s_uart,
        "[sched]    No thread left on a node; dispatcher exiting\n");
  return 0;
}

extern "C" int64_t compartment_main(Capability arg) {
  Capability* rw = rw_table();

  s_self_comp = rw[compartment::SLOT_SELF];
  Capability vm_quota = rw[SLOT_VM_QUOTA];
  s_seal_auth = rw[SLOT_SEAL_AUTH];
  Capability gate_sentry = rw[SLOT_SYS_SENTRY];
  Capability naming_publish = rw[SLOT_NAMING_PUBLISH];
  s_gate_alloc = rw[SLOT_SYS_VM_ALLOC];
  s_gate_dealloc = rw[SLOT_SYS_VM_DEALLOC];
  s_gate_switch = rw[SLOT_SYS_THREAD_SWITCH];
  s_gate_trap_wait = rw[SLOT_SYS_TRAP_WAIT];
  s_gate_thread_tid = rw[SLOT_SYS_THREAD_TID];
  s_gate_thread_kill = rw[SLOT_SYS_THREAD_KILL];
  s_gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  s_uart = rw[SLOT_UART_SENTRY];

  if (!sealing::is_sealed_as(OType::Compartment, s_self_comp) ||
      !sealing::is_sealed_as(OType::QuotaVm, vm_quota) ||
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
  iface->interrupt = nullptr;
  iface->irq_route = nullptr;

  // 1. Root node: the whole machine, funded from our own VM quota.
  QuotaSched* root = alloc_node(vm_quota, nullptr, init::SCHED_ROOT_PERIOD_US,
                                init::SCHED_ROOT_PERIOD_US, init::PRIORITY_RT,
                                init::SCHED_PERMANENT);
  if (root == nullptr) {
    return -1;
  }

  // 2. Entry points, published by name; `run` goes back to init only.
  auto entry = [&](const void* fn) {
    return mint_entry(s_gate_invoke, gate_sentry, s_self_comp, fn);
  };
  auto publish = [&](const char* name, const void* fn) {
    publish_name(s_gate_invoke, naming_publish, name, entry(fn));
  };
  publish("sched.quota_derive",
          reinterpret_cast<const void*>(&sched_quota_derive_entry));
  publish("sched.quota_destroy",
          reinterpret_cast<const void*>(&sched_quota_destroy_entry));
  publish("sched.quota_query",
          reinterpret_cast<const void*>(&sched_quota_query_entry));
  publish("sched.thread_register",
          reinterpret_cast<const void*>(&sched_thread_register_entry));
  publish("sched.yield", reinterpret_cast<const void*>(&sched_yield_entry));
  publish("sched.block", reinterpret_cast<const void*>(&sched_block_entry));
  publish("sched.wake", reinterpret_cast<const void*>(&sched_wake_entry));
  publish("sched.thread_kill",
          reinterpret_cast<const void*>(&sched_thread_kill_entry));
  publish("sched.lock_wait",
          reinterpret_cast<const void*>(&sched_lock_wait_entry));
  publish("sched.lock_wake",
          reinterpret_cast<const void*>(&sched_lock_wake_entry));

  iface->root_quota = seal_node(root);
  iface->run = entry(reinterpret_cast<const void*>(&sched_run_entry));

  // 3. Interrupts: `init` creates the handler's thread on this entry and
  //    installs it (irq.hpp).
  iface->interrupt =
      entry(reinterpret_cast<const void*>(&sched_interrupt_entry));

  // 4. Device interrupts (DEVICE INTERRUPTS): this hart's M-mode PLIC
  //    context, from the device tree, with every priority let through.
  //    Sources stay off until `irq_route` turns them on. Without a usable
  //    window nothing is routed, and the drivers poll.
  const Capability plic = rw[SLOT_PLIC_MMIO];
  const uint64_t hart = this_hart();
  const uint64_t ctx = iface->plic_ndev == 0         ? 2 * hart
                       : hart < platform::MAX_HARTS ? iface->plic_m_context[hart]
                                                    : platform::PLIC_NO_CONTEXT;
  if (capability_is_valid(plic) &&
      capability_has_perms(plic, perms::Load | perms::Store) &&
      ctx != platform::PLIC_NO_CONTEXT &&
      capability_get_length(plic) >= platform::plic_window_for_context(ctx)) {
    s_plic = plic;
    s_plic_context = ctx;
    if (iface->plic_ndev != 0) {
      s_plic_ndev = iface->plic_ndev < platform::PLIC_MAX_SOURCE
                        ? iface->plic_ndev
                        : platform::PLIC_MAX_SOURCE;
    }
    *plic_reg(platform::PLIC_CONTEXT_BASE +
              ctx * platform::PLIC_CONTEXT_STRIDE) = 0;  // threshold
    iface->irq_route =
        entry(reinterpret_cast<const void*>(&sched_irq_route_entry));
  }

  print(s_gate_invoke, s_uart,
        "[sched]    Scheduler online: root quota minted, sched.* published\n");
  return 0;
}

}  // namespace signetos::user
