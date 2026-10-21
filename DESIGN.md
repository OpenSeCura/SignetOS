# SignetOS Design

SignetOS is a single-address-space, single-privilege-level capability microkernel
for CHERI RISC-V. Isolation is enforced by CHERI capabilities only; the MMU is
used for backing memory, never for protection.

> **This is a living design document.** It is a snapshot of the current
> state of the work: the design as we understand it today, alongside what the
> implementation actually does. Both are expected to change, sometimes
> substantially, as the research progresses.

SignetOS is an **early, work-in-progress** system. Plenty of what follows is
scaffolding, placeholders or deliberate shortcuts. Read it as the current direction rather than a finished product.

---

## Contents

0. [Repository, build and run](#0-repository-build-and-run)
1. [Architecture and design goals](#1-architecture-and-design-goals)
2. [Core abstractions](#2-core-abstractions)
3. [System scenarios](#3-system-scenarios)
4. [Kernel mechanisms and security invariants](#4-kernel-mechanisms-and-security-invariants)
5. [System call and service interface reference](#5-system-call-and-service-interface-reference)
6. [Directions under investigation](#6-directions-under-investigation)

---

## 0. Repository, build and run

### 0.1 Current target and toolchain (eventual target is CherIoT)

* **ISA:** pure-capability CHERI RISC-V; freestanding C++ with no libc.
* **Required ISA extensions** (patched LLVM and QEMU, see `toolchain/setup.sh`):
  * `Zyseal`: seal/unseal instructions and permissions plus a small hardware
    object-type field. All kernel handles are hardware-sealed with it (§2.1).
  * `Zylevels1`: capability levels (global/local), used for stack-bound
    capabilities (§2.1).
  * `sentries`: the link a call writes is a return sentry (CT 2). Only a
    return can use one, a return can use nothing else, and it is local, so
    only a stack can hold it. Code never runs from a local capability
    (`toolchain/sentries`).
  * `mmodemmu`: lets M-mode use the MMU (`toolchain/mmodemmu`). Everything
    runs in M-mode, and this is what keeps paging.
* **Machine:** multi-hart QEMU `virt` with one virtio-blk disk (`disk.img`).
  There is no firmware (`-bios none`). The kernel starts in M-mode and stays
  there, takes every trap itself (nothing is delegated), and drives the CLINT
  timer and IPIs directly.

### 0.2 Source layout

| Path | Contents |
| --- | --- |
| `kernel/` | The microkernel proper: boot, syscalls, the domain switcher (`switcher.cpp` + `switch.S`), entry records (`sentry.cpp`), compartments, quotas, threads, VM and frame allocator, revocation, trap dispatch and fault delivery (`trap.cpp`), the two interrupt handlers and each hart's interrupt state (`irq.cpp`), unwinding. It does not print: it reports through `debug/report.hpp`. |
| `kernel/hw/` | Drivers for the board: the console (`uart.cpp`), timer and cross-hart poke (`clint.cpp`), DTB discovery (`platform.cpp`) |
| `kernel/debug/` | Diagnostics and checks: everything the kernel prints (`report.cpp`), the outbound capability check (`inspect.cpp`), boot self-tests (`quota_selftest.cpp`) |
| `kernel/lib/` | Freestanding C library routines (`kstring.cpp`) |
| `include/signetos/` | Kernel headers (`types.hpp` holds `OType`, `Status`, perms), with `hw/` and `debug/` mirroring the sources |
| `include/libc/` | The few freestanding helpers used in place of a libc |
| `user/` | Shared user-space runtime: `abi.hpp` (every cross-compartment request struct and slot layout), `manifest.hpp`, `runtime.hpp`, `entry.S` (image trampoline), `compartment.ld` |
| `boot/` | Compartments **embedded in the kernel image** |
| `external/services/` | Services loaded **from disk** |
| `external/apps/` | Programs loaded from disk |
| `tools/signetfs.py` | Builds and inspects the on-disk filesystem |

### 0.3 Building and running

```
make                 # kernel + all compartment images
make disk            # (re)build disk.img from external/
make term            # run under QEMU in the terminal
make clean
```

Options: `TRACE_SWITCH=1` prints every thread switch; `SMP=n` sets the hart
count.

---

## 1. Architecture and Design Goals

### 1.1 High-level architecture

| Design goal | Today |
| --- | --- |
| **Single virtual address space**: kernel, services, drivers and applications share one 64-bit space; no page-table switches | One root page table; nothing is remapped on a context switch. |
| **Single privilege level**: everything runs at one CPU privilege level; only the kernel holds ASR | Everything runs in M-mode with permissive page-table entries; the only thing separating compartments is CHERI. Only kernel entry points run with ASR (§2.5). |
| **CHERI-enforced isolation** | Bounds, permissions, sealing and tags are the only isolation mechanism. |
| **Thread migration model**: threads are not owned by compartments and migrate through a domain switcher | `sys_compartment_invoke` is the switcher (§3.4). A thread's kernel stack records the calls and traps it is inside; nothing records which compartments (§2.2, Lifecycle). |
| **Capability system call interface**: syscalls are cross-compartment invocations into the kernel | Kernel syscalls are entry points (§2.5) invoked through the *same* switcher gate as any other compartment call. That gate is the only hardware sentry the kernel gives a compartment. |
| **Zero-kernel-heap architecture** | There is no `kmalloc`. Every kernel object (quota node, compartment, thread, entry page) is whole pages billed to the requester's quota (§4.3); the only static roots live in `.bss`. |

### 1.2 The system as it runs today

```
 hardware  ──►  kernel (M-mode, ASR)  ──►  init (embedded)
                                             │  creates the core services
                                             │  (drivers, fs, naming,
                                             │   sched, trap_mgr, shell)
                                             │  publishes sched.run, exits
                                             ▼
                      kernel host loop re-dispatches sched.run
                                             │
                               sched picks threads ──► shell (console)
                                                        └─ run /bin/hello, /bin/logo
```

The present build makes these simplifications, each expanded below:

* **One hart does all the work.** Secondary harts are brought up and then
  park (§4.4).
* **The scheduler is currently round-robin** with per-node budgets,
  lazy replenishment and budgets enforced at the kernel's 10 ms tick (§2.6).
* **A revocation sweep runs when someone asks, and at most once per interval.**
  Freed memory is quarantined, stays mapped and stays charged to whoever paid
  for it until a sweep reclaims it (§4.2).
* **A fault is handled by the faulting compartment**, through the fault
  handler it installed, or reported and unwound if it has none: the caller
  gets `Faulted` (§3.6). Only a fault in kernel code halts the machine.

---

## 2. Core Abstractions

**Guiding principle: keep kernel state to a minimum.** The kernel keeps
almost no state of its own. The descriptors described below (the compartment
descriptor, the thread descriptor, the quota nodes, the ownership range
chains and the entry records) are not kernel tables that the kernel walks or
looks things up in:

* Each is an object in memory billed to whoever asked for it (§4.3).
* Each is reached only through a sealed handle that the requester holds and
  presents. On every call the kernel unseals the handle, trusts what it finds
  because nothing but the kernel can unseal it, and acts on that one object.
* There is no global list of compartments or threads, and no lookup by name
  or ID.
* When the last handle is gone and the object is destroyed, nothing in the
  kernel remembers it.

What the kernel genuinely owns is small and fixed:

* the frame allocator and the VA pool;
* the root vm quotas;
* per-hart CPU state;
* the trap table;
* the revocation bitmap holding the marks, whose pages each
  revocable allocation pays for (§4.2).

The rest of the design follows the same rule:

* Scheduling state lives entirely in the scheduler (§2.6).
* Disk and CPU quota trees live in their managers (§2.4).
* Compartment-minted sealing types cost the kernel no memory at all (§2.7).

The present descriptors are a first cut. Shrinking them further, or moving
more of what they hold out of the kernel's hands, is an ongoing goal.

### 2.1 Capability types

SignetOS uses the hardware object type (`CT`, currently a few bits under
Zyseal, but this is an area of active investigation!) to distinguish the
handles of its resource managers. Each hardware type belongs to the manager of
that resource, which holds the authority to seal and unseal it. The kernel
delegates `QuotaSched` and `QuotaDisk` to the user-space scheduler and
filesystem via `init` (§2.8, §5.8), and holds the remaining hardware types
itself.

Sealed types managed by the kernel:

| `OType` (`types.hpp`) | C type name | What it is |
| --- | --- | --- |
| `Sentry` | — | A hardware sentry (jumpable). The only one the kernel hands out is the switcher gate; compartments can make their own over their own code (§2.5). |
| `QuotaVm` | `capability_quota_vm_t` | Hierarchical virtual-memory budget (§2.4). |
| `QuotaThreadMem` | `capability_quota_thread_mem_t` | Budget for thread stacks and thread state (§2.4). |
| `Compartment` | `capability_compartment_t` | Handle to a compartment (§2.2). |
| `Thread` | `capability_thread_t` | Handle to a thread; Load → switch to it, Store → kill it. |
| `TypeKey` | `capability_type_t` | Compartment-minted type key (§2.7). |
| `SealedObject` | `capability_sealed_t` | Compartment-sealed object (§2.7). |
| `EntryPoint` | `Sentry` | Sealed pointer to an entry record describing a compartment or kernel entry point (§2.5). |
| `Trap` | — | Per-vector trap authority minted at boot (§3.6). |

Sealed types managed by user-space services, which hold the authority to
seal and unseal them:

| `OType` (`types.hpp`) | Manager | What it is |
| --- | --- | --- |
| `QuotaSched` | scheduler | CPU-bandwidth quotas (§2.4, §2.6). |
| `QuotaDisk` | filesystem | Disk quotas and open-file handles (§2.4, §5.7.3). |
| `QuotaHeap` | heap allocator | Reserved for the heap allocator (§5.7.1), which does not exist yet. |

**Permission convention on handles:** `Permit_Load` is the *operational*
right (use it) and `Permit_Store` the *administrative* right (derive from it,
destroy it, kill it). Quotas, threads and type keys all follow it.

#### Global vs. local capabilities

Stack-bound ("local") capabilities work as follows:

* A thread's stack capability is made **local** at creation.
* Every memory view a compartment receives (image memory, `sys_vm_allocate`
  results) has `StoreLocal` stripped, so a stack-derived capability can only
  be stored into a stack.
* The switcher identifies a genuine stack by the presence of `StoreLocal`
  (§3.4).
* The kernel keeps nothing local: it refuses local sources for `sys_cow` and
  for thread arguments, and trap bindings may not be local.

A caller can therefore lend a buffer for the duration of a call by handing
over a local capability (§4.2 model 1). The runtime does not yet use this
systematically.

### 2.2 Compartments

A compartment is a protection domain. It holds memory regions, a private
**capability table** that is its root of authority, and a descriptor that
the kernel reaches through the compartment's sealed handle.

**In memory:** a compartment is currently one page, holding the descriptor
followed by the capability table. It grows to more pages if a
large seed array is passed. The pages are billed to the compartment's funding
`QuotaVm`. The descriptor holds the funding quota, the chain of owned
ranges, the chain of entry pages, the UID and liveness flags, and the
compartment's fault handler (§3.6), which only the kernel writes. It
does not
record which threads are inside it, or how many. The kernel keeps no global
list of compartments, or of threads.

TODO: a capability table is currently 1 page!!!! That's not really very useful right now.

#### Capability table layout

| Slot | Contents |
| --- | --- |
| 0 | The compartment's own handle. |
| seeds (from 1) | The `initial_capabilities` array, in order, exactly as the creator supplied it. By convention seed *i* is manifest entry *i* (§2.8). |
| after the seeds | Free for the compartment's own use. |

Slot 0 is the only slot the kernel fills. It copies the seeds without giving
them any meaning: which quotas a compartment holds, and where, is agreed
between its creator and its image (§2.8). The funding quota pays for the
table but is not put in it. A compartment that allocates asks for its VM
quota in its manifest (`QUOTA_VM`), as it asks for thread memory
(`QUOTA_THREAD`) and CPU bandwidth (`QUOTA_SCHED`), and its creator derives
each one from its own.

The whole table is one writable region reached through `cgp`. Slot 0 is not
write-protected yet.

#### Ownership tracking

The memory a compartment owns is recorded on a chain of **range pages**,
billed to the funding quota. A second chain of **entry pages** holds entry
records (§2.5). Lookups are linear scans, which is a known TODO, and the
chains only grow while the compartment lives.

#### Lifecycle

* `sys_compartment_create(quota, seeds)` fills slot 0 and the seeds,
  assigns the UID and bills the pages to `quota`.
* `sys_compartment_destroy(comp)` marks the compartment as no longer live
  (its handle stops working at once), then:
  * **Succeeds whatever threads are inside.** Their code and table are
    quarantined, not unmapped, so they keep running until the revocation
    sweep (§4.2) clears every capability into the compartment, including the
    return addresses saved on kernel stacks. After that, a return into the
    compartment is unwound by the kernel (`unwind.hpp`): the dead frame is
    popped and the nearest live caller receives `ERR_COMPARTMENT_DESTROYED`
    (`Status::CompartmentDestroyed`) in `a0`. A trap handler's frame is
    resumed if the code it interrupted is still live (as if the handler had
    returned) and skipped otherwise. A thread with no live frame left ends,
    and a thread that has not started yet ends at its first instruction.
  * Purges the compartment's trap bindings.
  * Releases every owned range, its entry pages and its own pages by
    **quarantining** them (§4.2). Whoever paid for each is refunded when
    the sweep reclaims it.
  * The call returns nothing, so failures are silent. A stale handle is
    refused because the compartment is no longer live.

Any sealing types a compartment minted die with the memory that holds their
records (§2.7).

### 2.3 Threads

A thread is an execution context: registers, PC and stack. Threads do not
belong to compartments. They are funded from a `QuotaThreadMem`, scheduled by
the user-space scheduler under a `quota_sched` node, and migrate freely
between compartments. The quotas themselves belong to compartments, held in
their capability tables (§2.2): a thread is paid from, and registered under,
the quotas its creator passes when it makes and registers it.

| Element | Description |
| --- | --- |
| Descriptor | The thread's descriptor (saved registers and bookkeeping, reached through the thread handle) sits at the front of its allocation; the rest is a small **kernel return stack** that holds only switcher and trap frames. Syscall bodies run on a slice of the **caller's own stack**, not on the kernel stack (§3.4). Nesting depth is bounded by this stack; when it runs out, the call is refused with `NoKernelStack`. |
| Thread stack | Allocated from the same quota and made local (§2.1). When the thread migrates, the switcher narrows the stack so the callee sees only the unused part below the current stack pointer. |
| TLS | Not implemented yet.|
| Billing | State and stack are debited from the `QuotaThreadMem`, and refunded when the sweep after teardown reclaims them. |
| Identity | A kernel tid, never reused, exposed by `sys_thread_tid`. The scheduler keys its tables by it. A thread can read its own tid from `utidc` (CSR 0x480) without a call: the kernel writes the hart number and the running thread's tid there on every switch, and only the kernel can write it (`runtime.hpp`, `self_tid`). |
| Hierarchical CPU bandwidth | A parent derives a child `quota_sched`, creates the thread and registers it under that quota (§2.6, §3.3). When the parent destroys the child quota, its bandwidth returns to the parent node and the threads on it stop until they are registered elsewhere (§2.4, §2.6). |
| Exit | `sys_thread_exit` quarantines its memory (refunded at the next sweep) and **always returns to the host context**. The host loop then re-dispatches the scheduler (§2.6). |
| Kill | `sys_thread_kill`. A thread that never ran is torn down at once. Otherwise it is marked, and the kernel acts on the mark each time it resumes compartment code on it (return from a call, end of a trap) (`unwind.hpp`, KILLED THREADS). See the table below. `sched.thread_kill` wakes the thread and keeps it from sleeping again, so a kill takes effect within a tick of its CPU time. A stopped thread (§2.6) is put on the killer's node first, so the killer pays for it to run to its end. |

A kill means **return this thread to its owner**. Code about to resume on a
killed thread:

| Code | Result |
| --- | --- |
| The thread's own compartment, inside no call | The thread ends. |
| Anything it has called (a compartment, a system call, a trap handler) | Runs on to its return. A kill never cuts a call short. |

**What killing a thread is for.** Of the two things one might want from
it, kill provides only the last:

| Want | Provided by | Needs kill? |
| --- | --- | --- |
| Stop it using CPU/misbehaving | The scheduler: take back its node, and it is not picked again from the next tick. A compartment's PCC has no `AccessSystemRegs`, so it cannot mask the tick. | No |
| Get its memory back | The thread's state page and stack are held until it ends. Kill is what makes it end. | Yes |

So a kill is a request to reclaim one thread's memory, and it is bounded:
a thread that never comes back costs its creator exactly one stack plus the
state page, accounted to its `QuotaThreadMem`, and nothing more.

**How a kill plays out**, by where the thread is when it lands:

| Where the thread is | What happens | Guaranteed by |
| --- | --- | --- |
| In its own code, spinning or not | Ends at its next resume: the next tick at the latest. | The kernel (`unwind.hpp`, KILLED THREADS). The code may be arbitrary; it cannot prevent this. |
| Blocked in a service (`sched.block`, `lock_wait`) | The wait fails at once with `SCHED_KILLED`; the service returns an error on its ordinary error path, releasing what it held; the thread comes back up to its own code and ends. | The scheduler, plus the service returning when its wait fails. |
| Computing in a service | The service finishes and returns; then as above. | The service's work being bounded. |
| Spinning in a compartment that neither returns nor waits | Nothing. The thread stays; the killer learns it is still there (`sys_thread_tid` is not 0) and knows which compartment has it. | Not guaranteed. A trusted service doing this has a bug; an untrusted compartment is destroyed by its owner, and the thread is unwound past it. |



### 2.4 Quotas and allocation authorities

Resource management is decentralised; there is no single ledger. Each
resource manager owns a quota tree in its own dimension: bytes, CPU bandwidth,
or disk space etc.

**Principles**

1. **Caller-funded nodes.** A quota node is memory, whatever dimension it
   governs, so it is billed to a memory quota supplied by the caller and never
   to the manager. A manager funds only its own internal tables, from its own
   VM quota.
2. **Opaque to clients.** To holders a quota is a sealed capability; only its
   manager can open it.
3. **Load / Store.** `Permit_Load` grants operational authority (allocate,
   consume, schedule against it); `Permit_Store` grants administrative
   authority (derive children, destroy). `quota_sched` is the exception: it
   has one kind of handle, and destroying a node takes its parent's
   (`quota_sched` node, below).
4. **Immutable partitions.** Budgets are fixed at derivation. There is no
   resize and no renegotiation (§3.5).
5. **No reparenting.** Destroying a node never moves its children to another
   parent. What else it does is the manager's policy. The kernel's memory trees **close**:
   a destroyed node and every node beneath it refuse new charges and
   derives, every unused byte in the subtree returns to the destroyed node's
   parent at once, a closed node keeps only what is outstanding and passes
   every later refund straight to its first live ancestor, and it is freed
   when nothing is outstanding, because memory can only come back through
   the revocation sweep. `sched` **cascades**: destroying a node frees it and its
   subtree at once and their bandwidth goes back to the parent, because
   bandwidth is a promise the parent needs back at once. The threads on them
   stop, which is free (§2.6).

#### The kernel's quota tree

The kernel has **one generic tree** (`quota::Tree`), instantiated once for
`QuotaVm` and once for `QuotaThreadMem`. Each node is a kernel page that holds
the tree links, the node's allowance, and what it has handed out of it. A
child node is just another thing handed out: it counts for its own allowance
plus the cost of its page, so there is one ledger, not one for allocations
and one for children.

* **Conservation:** handed out ≤ allowance.
* **Node funding:** deriving a child debits the child's budget *plus the cost
  of the node page itself* from the parent. Runaway derivation is therefore
  bounded by the parent's budget. The budget comes back when the node is
  freed; the page, which is quarantined, when the sweep reclaims it.
* **Destroy** requires `Permit_Store` and nothing else. It closes the node
  and every node beneath it: no more charges or derives through any of them,
  and every unused byte at every depth is refunded to the parent in the same
  call. What the subtree funded (allocations, threads) carries on and keeps
  refunding into it, and **a closed node never holds unused allowance**: each
  refund into it passes straight through closed ancestors to the first live
  one. A node is freed when it holds nothing, and if that leaves a closed
  parent holding nothing, the parent is freed too. A quota that funded a
  long-lived allocation stays, closed, until that allocation is freed; it is
  never a reason to refuse.
* **Locking:** every node has its own lock and nothing locks a whole tree, so
  there is no lock that every holder of a quota has to get through. Charge,
  refund and derive each lock one node, and allowance going back up the tree
  locks one node at a time. Destroy also holds the locks on its path down
  the subtree it is closing, so the only work it can hold up is inside that
  subtree.

#### The five quota kinds (so far, there will be more and at finer granularity!!!!)

| Quota | Manager | Sealing | Description |
| --- | --- | --- | --- |
| `quota_vm` | kernel VM | `OType::QuotaVm` | As above. The root covers all pool memory left after boot. |
| `quota_thread_mem` | kernel threads | `OType::QuotaThreadMem` | As above. The root is carved out of the VM root at boot. |
| `quota_heap` | heap allocator | `OType::QuotaHeap` | Sub-page allocation budgets. **Does not exist yet**: there is no malloc and no sub-page allocator. |
| `quota_sched` | scheduler (user space) | `OType::QuotaSched` | CPU bandwidth. |
| `quota_disk` | filesystem (user space) | `OType::QuotaDisk` | Disk space and inodes. |

When the dimension is not memory (`quota_sched`, `quota_disk`), the caller
passes a `node_funding` `QuotaVm`. The manager allocates the node page against
it with `sys_vm_allocate(manager_comp, node_funding, …)`, so the bytes are
debited from the caller while the mapping and its capability stay with the
manager. Destroying the funding quota while nodes are live does not take them
away: the quota closes and is freed once the manager releases its pages.

##### `quota_sched` node

A node holds a budget and period (C/T), the bandwidth delegated to its
children, a priority class, the budget left for the current period (or the
overrun it still owes, §2.6), and until when its parent may not take it back.
The root covers 100 % of CPU bandwidth, is in the `RT` class and is
permanent. It is funded from the scheduler's own quota.

There is one kind of handle to a node, and whoever holds it can register
threads on it, derive children from it and query it. A child is never in a
more urgent class than its parent. Taking a node's time back needs its
parent's handle (`sched.quota_destroy(parent, child)`), so a holder can never
revoke its own node or anything above it. When it derives a child, the deriver
chooses how long the child is guaranteed:

| Kind | Can be destroyed | Use it when |
| --- | --- | --- |
| Revocable | at any time | The deriver needs control and the work can wait: untrusted programs, background work, its own workers. |
| Fixed term | once the term has ended | Both sides need protection for a while: a bounded job that must not be starved. |
| Permanent | never | Nobody should take it back, or nobody would be left to: `init`'s grants. |

A child's guarantee never outlasts its parent's. Destroying a node removes it
and everything derived under it, and the threads on them stop (§2.6).

##### `quota_disk` node

A node holds limits, usage and delegation for both space and inodes, plus
**the directory the node is rooted at**. Every node is confined to its path,
with no `..`. An I/O-rate limit is not tracked yet. The mapping from nodes to
the inodes they own lives in memory only and is **lost on reboot**; `init`
re-adopts `/home` at every boot (§3.1). Open-file records live in the node
page.

### 2.5 Entry points

The switcher enters another protection domain only through an **entry
record**: a small descriptor written by the kernel (`sys_sentry`) and named by
an `EntryPoint` handle sealed under a kernel type. The kernel keeps no
registry of entry points and never looks one up. The switcher trusts a record
because only the kernel can unseal the handle, and the compartment never gets
a writable capability to the record. The only bookkeeping is that the entry
pages sit on the owner's chain so they can be freed with it (§2.2).

An entry point is a record, not a bare sealed code pointer, because the
switcher needs more than a code address:

* which compartment it is entering, to find the callee's capability table;
* per-entry metadata, such as whether the entry is a trusted kernel entry and
  the minimum stack it requires.

A record therefore holds the entry's code capability, the callee's capability
table, the owning compartment (the canonical sealed handle, which the switcher
copies into the call's `ReturnFrame::callee_comp` so the trap path can tell
which compartment a fault came from), flags, and the minimum stack.

* `sys_sentry(comp, code)` requires `code` to lie in executable memory owned
  by `comp`. It writes a record on `comp`'s entry pages (billed to `comp`)
  and returns a sealed `EntryPoint` handle bounded to the record. The handle
  is not jumpable: it is a token presented to the switcher.
* A fault handler is not an entry record. Nothing but the kernel ever holds
  it, so there is no handle to seal: it is a code sentry kept in the
  compartment's descriptor (§3.6).
* The kernel's own system calls are records too, flagged `TRUSTED`. The
  kernel gives a compartment **one** hardware sentry, the switcher gate, and
  every domain crossing goes through it, kernel or not (§2.9).
* `user/runtime.hpp::mint_entry` is the usual way to make one: it re-bases the
  compartment's PCC onto a function and calls `sys_sentry`.

Records are the only way code crosses from one compartment to another.
Handing a peer raw code would let it jump in without a domain crossing: the
code would run on the peer's stack with the peer's capability table, with no
scrubbing and no return frame, and could still reach whatever its own code
capability covers, such as its GOT and through it its globals. So code -- a
plain code capability, or a call or return sentry, anything with Execute and
without AccessSystemRegs (`inspect::is_user_code`) -- never crosses through
the kernel:

* the switcher refuses a call whose arguments include code
  (`InvalidCapability`), and code a callee returns reaches its caller as
  `InvalidCapability`;
* `sys_thread_create` refuses code as `initial_arg`;
* code among a new compartment's seeds arrives untagged, as a local
  capability does.

One gap remains: memory two compartments share. A compartment can still store
its code there for the other to load. Closing that needs the hardware, for
example by letting code capabilities be stored only where local ones can.

Everything the switcher does *with* an entry is described in §3.4.

### 2.6 The Scheduler Compartment

Scheduling lives entirely in user space (`external/services/sched.cpp`). The
kernel keeps **no** scheduling state and never picks a thread. It provides
`sys_thread_switch`, a timer tick delivered to the scheduler, and a host loop
that re-dispatches the scheduler's thread whenever a thread exits; the
scheduler also uses `sys_thread_tid` and `sys_thread_kill`, and reads which
thread is running from `utidc`.

1. **Sealing authority.** The scheduler seals and opens `quota_sched`
   handles.
2. **Hardware preemption.** The scheduler hands its tick handler back to
   `init` in its handshake, and `init` installs it for the timer interrupt
   (`sys_trap_install`, §3.6). The kernel owns the tick period (10 ms) and
   re-arms the timer.
3. **Thread tables and bandwidth tracking in user memory**, debited with no
   syscalls.
4. **Ordering.** Priority classes are strict. Within a class the node served
   longest ago goes first, and within a node the thread chosen longest ago.
5. **Exhaustion and replenishment.** A node gets its budget back every
   period. It is charged at every tick and every switch, and a node with no
   budget left is not picked, so it can overrun by up to a tick. The overrun
   is carried into the next periods as a debt of at most a tick, so over time
   a node gets its share even when its budget is small next to the tick.
   A thread whose node is out of budget waits for the next period when it
   yields, blocks or waits for a lock: when nothing else can run, the CPU
   idles rather than hand out time nobody was promised. A thread that never
   yields keeps the CPU while nothing else can run (the tick handler cannot
   idle); that spare time, like idle time, is billed to nobody.
6. **Dispatch** via `sys_thread_switch`, including from inside the tick
   handler. A preempted thread then parks in its trap handler until it is
   picked again. The tick handler stands down while an entry point is
   updating scheduler state on the interrupted thread, and when the
   interrupted thread is not the one the scheduler last switched to.
7. **Allowance reclaim.** Destroying a sub-quota returns its bandwidth, and
   that of everything derived under it, to the parent at once. Its threads
   **stop**: they keep their state and their registration but are never picked
   for themselves, until their creator registers them on another node or
   kills them. They are not moved to the parent's node, which would make the
   whole subtree share the parent's own time.
8. **Bandwidth inheritance.** A thread waiting for a lock is still offered to
   `pick`, and when it is chosen the lock's owner runs in its place, charged
   to the waiter's node and in the waiter's class, following owners that are
   waiting in turn. That is how a stopped or depleted owner gets out of the
   way.
9. **Contended synchronisation.** A lock is a word in the memory of the
   compartment whose state it protects, holding the owner's tid, which a
   thread reads from `utidc` (the kernel keeps it up to date on every switch).
   Taking and releasing a lock nobody waits for is one compare-and-swap each
   (`runtime.hpp`, `lock` and `unlock`). Contention calls `sched.lock_wait`,
   and releasing with waiters calls `sched.lock_wake`, which hands the lock
   straight to the next waiter. If the owner ended holding the lock, the next
   waiter gets it with `SCHED_OWNER_DEAD`. A wait that would close a loop is
   refused with `SCHED_DEADLOCK`.

**What this asks of compartments:** a thread can be stopped in the middle of a
call into any compartment. A compartment that shares state between callers has
to protect it with a scheduler lock, as `fs` does. One that protects it some
other way can get stuck when a caller's node is destroyed.

**Admission** is checked at derive time: what a node hands out to its
children, each share normalised to its own period, never exceeds its own
budget. When nothing can run the scheduler spins instead of waiting for an
interrupt.

**Not built yet:**

* run queues: tables are static and every pick is a linear scan;
* a replenishment queue: replenishment is computed lazily at pick time;
* budget enforcement finer than the kernel's tick (item 5);
* `wake(tid)` is unprotected: **anyone may wake any tid**;
* a lock's waiters lend their time to whichever thread the lock word names,
  and a compartment can write any tid there. It can only give its own time
  away by it.

**Run loop:** `init` hands the scheduler's `run` entry point back to the
kernel. After `init` exits, the kernel creates a thread on that entry and
**re-dispatches it every time the running thread exits**. That is how the
scheduler learns about exits: it is resumed, asks the kernel which of its
threads have ended (`sys_thread_tid` returns 0), and forgets them. When no
registered thread is on a node any more, the run loop returns and the kernel
powers the machine off. Stopped threads (on no node) do not keep it running:
they are never picked, and only a thread that runs could move them to a node.

### 2.7 Compartment-minted sealing types

Hardware object types are scarce and assigned at boot. Any compartment can
still define its own object types, all sharing the one hardware type
`OType::SealedObject` (syscalls in §5.4).

1. **Type records.** A type is named by the address of a small record in the
   owner's own memory. The kernel never allocates it and never reads it.
   Uniqueness follows from ownership, so there is no registry, no global
   counter and no limit on how many types a compartment may define.
2. **Type keys.** `sys_type_mint` returns the record capability, bounded and
   sealed as `TypeKey`. The seal proves the kernel issued the key and stops a
   holder from retargeting it. `Permit_Store` authorises sealing,
   `Permit_Load` authorises unsealing, and `sys_type_derive` restricts these
   rights.
3. **Object layout.** A sealed object is a header followed by the payload. The
   sealed handle covers header and payload. The unsealed payload capability
   covers the payload alone, so a holder that can open an object cannot retype
   it.

   ```
   | header (tagged copy of the type key) | payload |
                                           ^ address of the sealed handle and of the payload
   ```

4. **Why the header holds a capability.** A plain type ID would be forgeable:
   the sealing compartment still holds a writable capability to the object,
   so it could overwrite the ID. A tagged capability sealed as `TypeKey`
   cannot be written by hand, because anything stored manually lands
   untagged.
5. **Sealing.** `sys_seal(key, obj)` requires `Permit_Store` on the key and a
   suitably aligned, capability-storing `obj` that spans header and payload.
   The kernel writes a permissionless copy of the key into the header and
   returns the sealed handle.
6. **Unsealing.** `sys_unseal(key, handle)` requires `Permit_Load` on the key.
   It returns the payload only if the header holds a **tagged** `TypeKey`
   whose address equals the key's. That is one capability load and a few
   register checks, and uses no kernel memory.
7. **Keep typed memory private.** Anyone with a capability to an object's
   backing memory can read its header, and anyone whose capability covers the
   record can mint the same type. Seal only memory you allocated.
8. **Permissions.** The hardware permissions of `obj` survive sealing and come
   back on unsealing. To delegate reduced rights, seal a second handle with
   fewer permissions.
9. **Lifetime.** A type lives as long as its record. When the record is freed,
   the revocation sweep untags every key and every header copy, so all objects
   of the type become unopenable at once. A sweep runs only when someone asks
   for one (§4.2), so until then a freed type stays openable.
10. **Provisioning at load time.** A creator can mint types for a compartment
    it is building and put the keys in its seeds. It follows that a creator
    can always open its child's sealed objects. **Sealing protects a
    compartment from its peers, not from its creator.** Nothing provisions
    types this way yet.

Users today: none in the default image (`sched` and `fs` now use their
dedicated hardware `OType`s; see §2.1, §2.4).

### 2.8 Images, manifests and the loader

#### Image format

An image is the file a compartment is loaded from; the compartment itself is
the protection domain the loader builds around it (§2.2). One image can be
loaded into many compartments. Today an image is a **flat binary** with a
small header. The header starts with a jump to the trampoline and also gives
a magic value, the extents of the capability relocations, read-only data, GOT
and BSS, the location of the manifest, and the offsets of the image's fault
handlers (0 for none).

* The trampoline (`user/entry.S`) sets up `cgp` and globals, then calls
  `compartment_main(Capability arg)`.
* Installing an image copies it and resolves its capability relocations;
  targets in read-only data get read-only capabilities.
* W^X: the PCC covers text, read-only data, relocations and GOT, page-padded
  so the bounds are exact. `.data` and `.bss` lie outside the PCC and are
  never executable.
* Fault handler (optional): an image may define `extern "C"`
  `compartment_error_handler(fault::ErrorState*)`. The header references it
  weakly, so in an image without one the field is 0, meaning "none", and the
  kernel unwinds every fault of that compartment (§3.6).
  `SIGNETOS_DEFAULT_FAULT_HANDLER` (`user/runtime.hpp`) defines the usual
  one.

#### The manifest (`user/manifest.hpp`)

A compartment holds exactly what the loader put in its capability table and
nothing else. An image therefore has to state what it wants in a form the
launcher can read before anything exists: the `.manifest` block, which the
header points to.

* The manifest gives the memory the image asks to run on, followed by a list
  of entries. Entry *i* lands in seed slot *i*, whoever launches the image.
* Entry kinds:
  * `SYSCALL`: a kernel entry.
  * `SERVICE`: a published entry point, by name (`"uart"`, `"fs.open"`, …).
  * `DISK`: a `quota_disk` node (space, inodes, rights, directory).
  * `FILE`: an open-file handle.
  * `MMIO`: a device window.
  * `DMA`: physically contiguous memory.
  * `IRQ`: an interrupt authority. (`EXC` remains in the format, but
    exceptions are not bindable and no launcher can meet it; §3.6.)
  * `QUOTA_VM`: the VM quota the compartment is funded from.
  * `QUOTA_THREAD`: a thread-memory quota.
  * `QUOTA_SCHED`: a `quota_sched` node (budget, period, class).
  * `ROOT`: one of the system's root quotas.
  * `OTYPE`: a hardware sealing authority (`OType::QuotaSched`, `OType::QuotaDisk`).

  Only `init` can meet the hardware and root kinds. The `QUOTA_*` kinds are
  how a compartment comes to hold its own quotas: its launcher derives each
  from its own.
* `MANIFEST_REQUIRED` tells the launcher not to start the image without that
  entry. Any other unmet entry becomes a null slot, and by design the program
  cannot tell "refused" from "unavailable".
* `SIGNETOS_MANIFEST(...)` is an X-macro that emits both the table and the
  matching `SLOT_*` constants, so the two cannot disagree.

**The manifest is a request, never an authority.** It is just bytes in a
file. The launcher (`init` for services, the shell's `run` for programs)
applies its own policy to every entry and derives every grant from what it
holds itself.

#### The loader (`user::create_compartment` in `user/runtime.hpp`)

Compartment construction is a library helper linked into any launcher (`init`
or `shell`) that holds the required syscall gates (`compartment_create`,
`compartment_destroy`, `vm_allocate`, `sentry`, `fault_install`). Given a VM
quota, a seed array and an image, `user::create_compartment`:

1. checks the manifest is well formed and matches the seeds;
2. creates the compartment;
3. installs the image into memory allocated from the same quota;
4. mints the entry point and installs the image's fault handler, if any
   (`user::load_compartment_image`; a failed install destroys the compartment
   and fails the load);
5. returns the compartment and entry-point handles.

Failures are silent (null outputs). Dependency resolution, such as looking
services up in `naming`, is the launcher's job when it builds the seeds.

---

## 3. System Scenarios

### 3.1 System boot and core services bootstrap

#### Kernel (`kernel/main.cpp`)

1. Select the boot hart and discover the DTB.
2. Set up the single page table:
   * the kernel image;
   * device MMIO;
   * a kernel-only direct map of RAM;
   * the dynamic VA pool, from which *all* dynamic memory, kernel objects and
     compartment memory alike, is carved.
3. Initialise the frame allocator, the sealing root and the root `QuotaVm`,
   then the remaining subsystems.
4. Bring up the secondary harts, which park (§4.4).
5. Create the root `QuotaThreadMem` from the VM root.
6. Create `init` with its seeds (§5.8) and hand it a boot manifest: the DTB,
   the device window, and the embedded images. Run it to exit, then drive the
   scheduler's run loop (§2.6).

#### `init` (`boot/init.cpp`)

`init` is policy. For each service it derives a VM quota of the size the
manifest asks for, then grants each manifest entry *if init has it*. Some
service images are embedded in the kernel and the rest are loaded from the
filesystem; which is which is a build detail.

| Step | Compartment | What init gives it |
| --- | --- | --- |
| 1 | — | Parse the DTB to find the UART, PLIC and virtio devices. |
| 2 | `uart` | Its MMIO window. Handshake returns its `read` and IRQ entries; init offers `uart` (print) and `uart.read`. |
| 3 | `blk` | The virtio MMIO window and a physically contiguous **DMA arena allocated by init** (`FLAG_DMA`). Handshake passes the arena's physical address and returns `read`/`write`/IRQ entries. |
| 4 | `fs` | Memory syscalls, `OType::QuotaDisk`, `uart`, `blk.read`/`blk.write`, and memory for its tables sized to the disk. It mounts the disk and creates the root `quota_disk`. |
| 5 | `naming` | Once it is up, init publishes `uart` and the `fs.*` entries. |
| 6 | `sched` | `OType::QuotaSched` and the timer trap authority. Afterwards init tells `blk` how to reach the scheduler so it can sleep instead of polling. |
| 7 | `trap_mgr` | The PLIC window and the external-interrupt authority. Init routes the UART and blk interrupt sources to their drivers; routing is init-only. |
| 8 | `shell` | Per its manifest: its VM quota, a thread-memory quota, a permanent `quota_sched` node (`INTERACTIVE`, 50 ms per 100 ms), `/home` as an ADMIN `quota_disk` (adopting what is already there), `/bin` as a read-only OP view, and the root quotas it asks for. Init then creates **the only thread it ever creates**: the shell's, paid from the shell's thread-memory quota and registered under the shell's node. |
| 9 | — | Hand `sched.run` to the kernel, scrub its own syscall entries, and exit. |

### 3.2 Creating and loading a new compartment

The launcher decides what the new compartment gets and calls
`user::create_compartment` directly:

```
Launcher (init / shell)                                                 Kernel
  |-- read image, parse .manifest                                         |
  |-- build seeds[] by policy                                             |
  |   (sys_quota_vm_derive, fs.quota_derive, naming.lookup, ...)          |
  |-- user::create_compartment(...)                                       |
  |     |-- sys_compartment_create(q, seeds) ---------------------------->|
  |     |<-- comp --------------------------------------------------------|
  |     |-- sys_vm_allocate(comp, q, size) ------------------------------>|
  |     |<-- zeroed RW memory --------------------------------------------|
  |     |   [copy image, resolve cap_relocs, derive PCC view: W^X]        |
  |     |-- sys_sentry(comp, pcc) --------------------------------------->|
  |     |<-- EntryPoint --------------------------------------------------|
```

1. **Derive the VM quota.** The launcher derives a quota from its own for the
   memory the manifest asks for, capped by its policy.
2. **Build the seeds.** For each manifest entry the launcher derives or looks
   up the grant (sub-quotas, disk nodes, service entry points) or leaves a
   null.
3. **Create the compartment.** `user::create_compartment` invokes
   `sys_compartment_create`; the compartment's pages are billed to the new
   quota (§2.2).
4. **Allocate and install.** It allocates zeroed memory owned by the new
   compartment, copies the image, resolves relocations and derives the W^X
   views (§2.8).
5. **Mint the entry.** `sys_sentry` returns the `EntryPoint` (and
   `sys_fault_install` installs any image fault handler).

### 3.3 Executing a compartment and thread scheduling

Once loaded, a compartment is passive; a thread has to enter it.

#### A. Starting an independent program (the shell's `run`)

1. Derive a `quota_sched` for the program under the shell's own node, with
   the bandwidth its manifest asks for (`QUOTA_SCHED`) within the shell's
   cap.
2. `sys_thread_create` on the program's entry, from the shell's thread-memory
   quota, which returns a suspended thread.
3. Register the thread with the scheduler under the new quota.
4. The scheduler dispatches the thread with `sys_thread_switch` when its
   class and budget allow.

The node is revocable. If its manifest asks, the program holds the node in its
own table too; the shell destroys it through its own node, which the program
does not hold. The program cannot reach `sched.*` or create threads yet, so it
cannot use the node to sub-delegate bandwidth to threads of its own. If it
could, destroying the node would take those nodes with it.

#### B. Using a compartment as a shared library

No new thread is involved: the caller invokes an `EntryPoint`, and the thread
migrates in and back out (§3.4). Every service call in the system (`fs.read`,
`uart` print, `naming.lookup`, …) works this way.

### 3.4 Cross-compartment invocation (thread migration)

```
Caller                       Switcher (switch.S + sentry.cpp)                 Callee
  |-- invoke(entry, a0..a4) -->|                                                |
  |                            |-- mask interrupts; check kernel-stack room     |
  |                            |-- push return frame                            |
  |                            |-- open EntryPoint, check record, W^X,          |
  |                            |   ASR only if TRUSTED, check owner is live,    |
  |                            |   narrow stack,                                |
  |                            |   inspect outbound capabilities (a0..a4)       |
  |                            |-- scrub non-argument registers                 |
  |                            |-- jump to entry, cgp = callee table ---------->|
  |                            |                                                |-- runs on narrowed stack
  |                            |<-- return via switcher gate (ca0 = ret) -------|
  |                            |-- validate frame (replay check)                |
  |                            |-- inspect return capability (ca0)              |
  |                            |-- scrub callee's stack region + volatile regs  |
  |                            |-- pop frame, restore caller state              |
  |<-- ret (or Status) --------|                                                |
```

1. **Call initiation:** the compartment jumps to the hardware sentry for the
   switcher gate, with the `EntryPoint` in `ca0` and up to five arguments in
   `ca1..ca5` (delivered to the callee in `ca0..ca4`).
2. **Validation:** the record must be live and the handle must carry
   `Permit_Load`. The code capability must be executable and not writable, and
   only `TRUSTED` (kernel) records may carry ASR.
3. **Caller state preservation:** a return frame holding the caller's
   callee-saved state is pushed on the thread's kernel stack. If there is no
   room, the call is refused with `NoKernelStack`.
4. **Outbound scrubbing:** every register except the arguments (`ca0..ca4`) is
   zeroed on the way into a compartment.
5. **Stack narrowing:**
   * A compartment callee gets *everything below the caller's stack pointer*.
   * A kernel entry gets a fixed-size slice below it, or `StackTooSmall` if
     the caller has less room.
   * The switcher recognises a real stack by `StoreLocal` (§2.1), and enforces
     the record's minimum stack.
6. **Domain entry:** `cgp` is set to the callee's table and execution starts
   at the entry. A compartment callee inherits the caller's interrupt-enable
   state; a kernel callee runs with interrupts masked.
7. **Return and inbound scrubbing:**
   * The switcher validates the frame; a bad or replayed return **kills the
     thread**.
   * It scrubs the **entire stack region the callee used** and all volatile
     registers except `ca0`, restores the caller's state, and returns the
     callee's `ca0` to the caller.
   * The return value (`ca0`) is checked by `inspect` (§4.5) before the caller
     sees it.

All stack zeroing is done in assembly (`switch.S`, `early_trap.S`): below the
callee's (or trap handler's) `csp` just before it is entered, and over the
whole slice it was lent when the frame that lent it is resumed. Unwinding past
dead frames zeroes only the slice of the frame it resumes, which covers every
slice carved above it. Popped kernel frames are not wiped: nothing reads a
frame once it is popped, and no compartment holds the kernel stack's bounds.

TODO: a compartment callee is lent everything below the caller's `csp`, and
that whole region is zeroed on entry and again on return (trap handlers too).
So the cost depends on how much stack the caller has free, not on how much
the callee uses. Kernel entries always zero their full 4 KiB slice. We need a
faster way to do this zeroing.

**Outbound capability policy (`kernel/debug/inspect.cpp`):** every capability
leaving the kernel, as an argument on the way in or a return value on the way
out, must:

* carry no seal/unseal authority (except narrow type authorities);
* respect W^X;
* not be an ambient root;
* if it is a sealed sentry, be the switcher gate or something small in dynamic
  space;
* if it is unsealed memory, lie in the dynamic pool, the device window or the
  read-only boot images.

**A violation panics the machine.** The check is a kernel bug detector, not an
error path.

### 3.5 Quota enforcement and fixed allocation limits

Quotas are strict, static partitions, both in the kernel's two trees and in
the scheduler's and filesystem's trees:

1. **Static derivation.** A budget is fixed for the quota's lifetime; neither
   parent nor child can resize it.
2. **Deterministic bounds.** An allocation that does not fit is rejected at
   once: `sys_vm_allocate` returns NULL, `fs` returns `FS_QUOTA`, and `sched`
   refuses admission.
3. **No runtime renegotiation.** A workload that needs a different footprint
   is torn down and re-provisioned by its supervisor.
4. **Reclamation.** Destroying a quota refunds the unused allowance of its
   whole subtree to the parent at once; the rest follows, refund by refund,
   as what it funded is freed.

Rough edges:

* The kernel syscalls carry no error channel beyond NULL / -1, so a caller
  cannot tell "out of quota" from "bad handle".
* Freed pages are quarantined rather than reused, and the quota that paid
  for them is refunded only when a sweep has reclaimed them (§4.2). An owner
  that needs the memory back sooner waits for one.

### 3.6 Hardware trap and interrupt handling

Interrupts and faults are routed differently. Only two interrupts leave
the kernel, each to one fixed handler. A synchronous fault goes to **the
compartment that raised it**, never to a global handler.

#### Interrupts (`include/signetos/irq.hpp`)

1. **Two handlers, installed by `init`:** the timer (the kernel tick) goes
   to the scheduler, and the external interrupt (every PLIC device) to the
   trap manager. The software interrupt is the kernel's own cross-hart poke,
   and nothing else can fire. `sched` and `trap_mgr` hand their handler
   entries back to `init` in their handshakes, and `init` installs each with
   `sys_trap_install(irq, EntryPoint)`. Nothing else is bindable, and there
   is no table, no unbind and no rebinding.
2. **Authority:** the `sys_trap_install` gate itself. `init` is seeded with
   every syscall gate and hands this one to nobody. Each handler can be
   installed once (`Busy` afterwards) and is never removed. An install is
   synchronised to all harts by IPI. If the handler's compartment is
   destroyed, its entry stops resolving and the interrupt is silenced on
   each hart where it arrives.
3. **Delivery:** a trap frame is pushed on the interrupted thread's kernel
   stack. The handler then runs **on the interrupted thread's own, narrowed
   stack**, masked, with `(mcause, mtval, mepc, mtval2)` as arguments. Its
   stack region is scrubbed on return. The kernel re-arms the tick before
   each timer delivery.
4. **Resolution:** the handler returns and the thread resumes. The
   scheduler's handler may instead `sys_thread_switch` away, and the thread
   then stays parked in its handler.

#### Per-compartment faults (`include/signetos/fault.hpp`)

Modelled on CHERIoT's per-compartment error handlers. The kernel provides
mechanism only: what a fault means, and what to do about it, is the
faulting compartment's business.

1. **Installation:** a compartment has at most one handler, held in a
   kernel-written field of its `Compartment` descriptor (`fault_handler`):
   a code sentry, checked as an entry point's code is (in the compartment's
   own memory, W^X, no ASR). It is installed with
   `sys_fault_install(comp, code)`, which returns a `Status`; installing
   again replaces it. It is not an entry record and no handle to it exists,
   so only the fault path can enter it. The loader installs it from the image
   header (§2.8) before the compartment's first instruction. A failed install
   fails the load.

   A handler is optional: a compartment without one has every fault
   reported by the kernel and unwound (6. below). Most images use the
   runtime's default,
   `SIGNETOS_DEFAULT_FAULT_HANDLER(name)` (`user/runtime.hpp`): the
   compartment's own code, which prints one line giving the compartment, the
   thread, the fault, the pc and the pc's offset in the image, then unwinds.
   The line goes to the console like any other output, by a call to `uart`
   through the compartment's own table. `uart`'s handler writes the same line
   straight to the device. `fault.bin` defines its own, to exercise every
   path.
2. **Which compartment faulted:** the frame directly beneath the fault's
   `TrapFrame` names it. Nothing the compartment controls (its `cgp`, its
   table) is ever used for identity.
   * A `ReturnFrame` gives `callee_comp`: the canonical handle the switcher
     copied from the entry record.
   * A `TrapFrame` gives `handler_comp`: the fault was in a handler.
   * At the bottom of a thread, it is the owner of the thread's entry
     sentry.

   `compartment::open` then checks that the compartment is still live.
3. **Delivery:** the kernel copies the faulting register file into a
   `fault::ErrorState` at the top of the stack below the faulting `csp`:
   `regs[n]` is xn, then `pc` (a plain address: the handler never holds the
   faulting PCC), `mcause`, `mtval` and `mtval2`, raw. The handler runs on
   the rest of that stack, below the `ErrorState`, with `ca0` = the
   `ErrorState` and `cgp` = its own table. The kernel does not interpret the
   fault; `fault::decode` turns `mcause`/`mtval2` into a class and, for
   CHERI faults, a violation and access kind, for handlers that want it.
4. **Verdict:** the handler returns one of two verdicts in `a0`:
   * `INSTALL_CONTEXT`: the kernel loads the register file back from the
     `ErrorState` and resumes at its `pc`. The resumed PCC is the faulting
     PCC with only its address changed, so a handler can move the program
     counter within its own code and nowhere else. Skipping the faulting
     instruction (`pc += user::instruction_length(pc)`), retrying it,
     repairing a register or jumping to a recovery point are all edits to
     the `ErrorState` before this verdict.
   * Anything else unwinds.
5. **Unwinding:** the faulting activation is abandoned and its scrubbed
   frames are popped. The caller's `sys_compartment_invoke` returns
   `Status::Faulted`. A thread whose own bottom-level code faulted ends.
6. **When the kernel unwinds without asking:** the fault is reported on the
   console and unwound as above. This covers:
   * no handler installed;
   * no room below the faulting `csp` for the `ErrorState` plus the
     handler's `min_stack`;
   * less than `RET_FRAME_MIN_FREE` of kernel stack;
   * a fault inside the handler itself: it is **never delivered again**.

   There is no limit on how often an activation may fault. A handler that
   keeps resuming code that keeps faulting is a busy loop like any other: no
   kernel state grows (`INSTALL_CONTEXT` pops the `TrapFrame` before the code
   runs again), the tick still preempts it, and a kill takes effect the next
   time the handler returns. A compartment that wants a limit counts in its
   own handler.

   A fault inside kernel code always halts the machine.
7. **Interrupt state:** a fault handler runs with the interrupted code's
   `MIE` when there is kernel-stack room for a nested trap (asm_macros.h,
   KERNEL-STACK ROOM). Otherwise it runs masked.

Demand-paging and CoW faults are meant to be resolved silently by the kernel
before this path. None exist yet (§3.7).

**The trap manager (`external/services/trap_mgr.cpp`):**

* Owns the PLIC and handles the external interrupt (`init` installs its
  handler), for the **boot hart only**.
* Keeps a small static routing table from sources to driver handlers. `init`
  fills it and the routing entry is not published. There is no unroute.
* On an interrupt it claims the source, invokes each routed handler, and
  completes the source.
* Has nothing to do with faults: those never leave the faulting compartment.

**Tests:** `run fault.bin skip|retry|fix|unwind|double|overflow|loop`
exercises each path in a program that defines its own handler: resuming
past, at, or with a repaired register; unwinding; a fault in the handler; no
room for the handler; and a handler that retries until its own limit. The shell's
`faulttest` faults inside a call into one of the shell's own entry points:
the shell's default handler reports the fault, and the call returns
`Faulted`.

### 3.7 Fork-less copy-on-write

`sys_cow` is a single-address-space copy-on-write primitive, decoupled from
any notion of `fork()`, for snapshots and pre-warmed runtimes:

```c
capability_t sys_cow(comp, mem_quota, src_memory, len);
```

1. **Up-front quota deduction:** `len` is debited from `mem_quota` at the
   call, so later writes can never fail for lack of quota.
2. **Page sharing:** the new range is meant to map the source's frames
   read-only with per-frame reference counts. Today the kernel instead
   allocates fresh pages and does a **synchronous copy**, keeping tags.
   `src_memory` must be global.
3. **On-demand resolution:** a write to a shared page is meant to fault, get a
   fresh frame (already paid for), copy and resume transparently. There is no
   store-fault handler yet (§3.6).

The page-fault-driven design, and anything like demand paging or a backing
store, is future work. Nothing in user space depends on CoW yet.

### 3.8 Termination and resource teardown

Tearing down a child reclaims everything and returns every allowance to its
parent. The shell does this after a program's thread has exited:

```c
// shell `run`, after the program thread is gone
sys_compartment_destroy(prog_comp);      // the program's thread has already exited
fs.close / fs.unlink / fs.quota_destroy  // program's files and /home/<prog> node
sched.quota_destroy(shell_sched, prog_sched);  // through the shell's own node
sys_vm_deallocate(image & buffers);
sys_quota_vm_destroy(prog_vm_quota);     // closes; freed once nothing it funded remains
```

| Step | Behaviour |
| --- | --- |
| Compartment destruction | Every owned range is **quarantined** (still mapped, never reissued) and reclaimed by the next sweep. The compartment's own pages too. Each funding quota is refunded as the sweep reclaims what it paid for. |
| Resident threads | Destroy does not wait for them: once the sweep has run, a thread returning into the destroyed compartment is unwound to its nearest live caller, which gets `ERR_COMPARTMENT_DESTROYED` (§2.2). The shell still **waits for exit** before tearing down, by polling `sched.quota_query` until no thread is registered on the program's node: destroying the node earlier would stop the thread, not end it. There is no join or timeout. A running program can be killed (§2.3). |
| `sys_quota_vm_destroy` | Closes the quota and its whole subtree and refunds every unused byte in it at once. Each node is freed, and the rest refunded, when everything it funded has been released. Fails only for a bad or already-closed handle or missing `Permit_Store`. |
| `sched.quota_destroy` | Called through the parent's handle. Frees the node and everything derived under it, returns their bandwidth to the parent and their pages to their funding grants. Threads still on them stop (§2.6). Refused only while a fixed term runs. |
| `fs.quota_destroy` | Cascade-unlinks everything the node owns; refused while child nodes exist. |
| Funding order | None required. A VM quota that funds another manager's nodes may be destroyed before them: it closes, and is freed once the manager releases the node pages. Destroying a compartment never takes manager-held nodes with it. |

The shell prints a warning when a step fails and carries on. In practice the
usual leak is physical memory held in quarantine until a sweep.

---

## 4. Kernel Mechanisms and Security Invariants

### 4.1 Domain switcher guarantees

| Invariant | Notes |
| --- | --- |
| 1. No outbound data leaks | Registers are scrubbed except the arguments. |
| 2. No return data leaks | All volatile registers *and the entire stack region the callee used* are scrubbed on return. |
| 3. Stack frame protection | The callee's stack is narrowed to below the caller's stack pointer. Local capabilities keep stack pointers from escaping. |
| 4. Control-flow integrity | Switcher-mediated entry happens only through `EntryPoint` records. Code never crosses a compartment boundary through the kernel: the switcher, thread creation and compartment seeds refuse it; memory two compartments share is the remaining gap (§2.5). |
| 5. Deterministic unwinding | Return frames live on the thread's trusted stack. The return path validates the frame chain and kills the thread on a mismatch. |


### 4.2 Capability sharing and memory revocation

| Model | Description |
| --- | --- |
| 1. Ephemeral borrowing (local capabilities) | A caller lends a buffer by passing a local capability in a register argument. The callee cannot store it outside a stack, and access ends with the call, so no sweep is needed. |
| 2. Persistent sharing via sealed handles | The owner seals handles under its hardware `OType` (§2.1) or a compartment-minted type (§2.7) and hands out handles that only it can open. Used for `fs` file handles and for both services' quota handles. |
| 3. Direct global sharing with quarantine + revocation | Raw global capabilities shared across compartments require the memory to be revoked before it is reused. |

**Revocation (`kernel/revoke.cpp`, `kernel/vm.cpp`):**

* **The base rule.** A sweep revokes every capability whose *base* lies in
  memory being taken back: a quarantined page, or a range marked with
  `sys_revoke`. Every capability derived from a range has its base inside it,
  so all of them die; a capability based outside it (the owner's capability
  to the enclosing allocation, the kernel's record of it) was not derived
  from it and survives. This is CHERIoT's rule.
* **Freeing a whole allocation** (`sys_vm_deallocate`, compartment destroy)
  quarantines it; that is all the registration it needs.
* **Revoking part of an allocation** (`sys_revoke(comp, mem)`) is for an
  owner that keeps the allocation and reuses the part, as a heap does with a
  freed object. The authority is the compartment handle: the range must lie
  inside one of `comp`'s revocable allocations (`FLAG_REVOCABLE`), and must
  not include its first byte, where the owner's own capability to it is
  based. `sys_revoke` returns the current epoch; the owner reuses the memory
  once `sys_revoke_query`, the count of completed sweeps, reaches it. Nobody
  else can revoke; whoever needs memory revoked asks its owner.
* **Marks.** `sys_revoke` sets one bit per 16 bytes of its range, so both ends
  must be multiples of 16 bytes; the sweep tests the bit under each
  capability's base, and clears them all when it ends. The bits are a
  bitmap of the virtual address space, at a fixed place in its top 2GB
  (`vm.hpp`, REVOCATION BITMAP), because capabilities name virtual addresses.
  Only revocable allocations have bitmap pages: one page per 512KB of
  allocation, rounded up, mapped with it, charged to its quota and freed with
  it. To keep each bitmap page to one owner, a revocable allocation starts on
  a 512KB boundary. Revoking itself costs no memory, and the sweep's test
  costs the same however much is marked.
* **Freed memory stays charged until it is reclaimed.** A quarantined range
  is still the freer's address space: nobody else can be given it until the
  sweep. So whoever frees memory owes it to the quota that paid for it: the
  bytes stay charged, counted as owed on the node. After each sweep has
  reclaimed, it walks the quota trees and refunds every node what it is owed
  (`quota.hpp`, OWED). Freeing in a loop therefore exhausts only the freer's
  own quota.
* **When a sweep runs:** nobody can ask for one. `sys_revoke_query()` sweeps
  before it answers, at most once per `revoke::SWEEP_INTERVAL_US` however
  many look. A sweep stops the machine while it scans all live memory, so the
  interval is what bounds the time sweeps take; who looks, and how often,
  cannot change it. Nothing
  else starts a sweep: `vm::alloc_pages` just fails when memory runs out. A
  compartment whose allocation fails because what it freed is still in
  quarantine waits for the next epoch and tries again (`runtime.hpp`,
  `revoke_wait`).

### 4.3 Architectural invariants

| Invariant | Notes |
| --- | --- |
| Capabilities are the sole source of authority; the MMU is never used for access control, only for backing, demand paging and CoW write detection | Page permissions are permissive everywhere. Demand paging and CoW write detection do not exist yet, so the MMU currently does *only* backing. |
| Accessibility invariant: never unmap under a valid capability | Quarantine keeps freed pages mapped until the sweep has cleared every tag. |
| Sealing type invariant: a compartment cannot open or forge an authority without holding the authority for its type | Kernel authorities and service quotas (`QuotaSched`, `QuotaDisk`) use hardware types. Compartment-minted objects use software types (§2.7), whose identity is a hardware tag and cannot be made by writing memory. |
| Immutable quota partitions | Quotas cannot be increased after derivation (§3.5). |
| Self-funding metadata | Compartments, threads, kernel quota nodes, entry pages, range pages, revocation backlog pages, scheduler nodes and fs nodes are all billed to the requester. The exceptions are page tables, which come from the frame pool, are never freed and are not charged, and each service's own static tables, which the service pays for from its own quota. |
| Deterministic quotas and write guarantees | All memory is backed at allocation time; nothing is lazy, so nothing can fail later. |

### 4.4 Multi-hart status

The kernel is written with SMP in mind:

* per-hart stacks and CPU state;
* spinlocks on shared structures;
* IPI-based synchronisation of each hart's interrupt state when an interrupt
  handler is installed (`irq.cpp`);
* atomic claiming of threads in `kill` and dispatch.

**Today, though, every thread runs on the boot hart; the secondary harts are
brought up and park.**

The revocation sweep (§4.2) relies on that. It runs with interrupts off and
assumes nothing else runs meanwhile. Once threads run on several harts,
another hart could, during a sweep:

* hold a revoked capability in a register, where the sweep never looks;
* copy a capability from a page the sweep has not reached yet into one it
  has already scanned;
* free memory after the sweep has scanned the pages that point into it, which
  the sweep would then reclaim along with the rest.

Sweeping with several harts running is still to be designed. One option is
to pause every hart briefly at the end of the sweep, to check registers and
the pages written during it. Another is hardware that checks capabilities as
they are loaded (CHERIoT's load filter).

## 5. System Call and Service Interface Reference

A system call is a cross-compartment invocation into the kernel through the
switcher gate (§2.5, §3.4). The canonical list is `SIGNETOS_SYSCALLS`
(`include/signetos/syscall.hpp`). `init` is seeded with every syscall, and
other compartments request the ones they need through `SYSCALL` manifest
entries. Unless stated otherwise, a failed call returns NULL/0 with no further
status.

### 5.1 Virtual memory and capability revocation

| Syscall (signature) | Behaviour |
| --- | --- |
| `capability_t sys_vm_allocate(comp, mem_quota, size, flags)` | Debits `mem_quota` and records the range as owned by `comp`. Returns a read/write capability bounded to the allocation, with `StoreLocal` stripped. Memory is always zeroed and at fresh addresses. `FLAG_DMA` makes it one physically contiguous run with its physical base in its first 8 bytes, for a device to be pointed at. `FLAG_REVOCABLE` makes it one whose parts can be revoked; it starts on a 512KB boundary and is also charged its revocation marks, one page per 512KB (§4.2). Any other flag is refused. |
| `void sys_vm_deallocate(comp, mem_quota, mem_capability)` | `mem_quota` must be the quota that funded the range. **Quarantines** the memory; `mem_quota` is refunded when the sweep reclaims it (§4.2). |
| `capability_t sys_cow(comp, mem_quota, src_memory, len)` | Debits `len` up front. Currently an **eager copy** that keeps tags (§3.7). |
| `uint64_t sys_revoke(comp, mem_cap)` | Marks `mem_cap`'s range for the next sweep, which revokes every capability based in it (§4.2). The range must lie inside one of `comp`'s revocable allocations, not including its first byte, and start and end on a multiple of 16 bytes. Returns the current epoch: the range may be reused once `sys_revoke_query` reaches it. 0 if refused. |
| `uint64_t sys_revoke_query(void)` | How many sweeps have completed, having swept first if `revoke::SWEEP_INTERVAL_US` allows (§4.2). |

### 5.2 Virtual memory quotas

| Syscall | Behaviour |
| --- | --- |
| `capability_quota_vm_t sys_quota_vm_derive(parent, amount_bytes, permissions)` | Needs `Permit_Store`. Debits the amount plus the node's own cost from the parent and returns the sealed child, restricted to `permissions`. |
| `int sys_quota_vm_destroy(quota)` | 0 on success, -1 otherwise. Requires `Permit_Store`. Closes the quota and every quota derived beneath it (§2.4): all their unused budget is refunded now, and each node is freed once everything it funded has been released. |

### 5.3 Thread memory quotas

| Syscall | Behaviour |
| --- | --- |
| `sys_quota_thread_mem_derive(parent, amount_bytes, permissions)` | As in 5.2, on the thread-memory tree. |
| `int sys_quota_thread_mem_destroy(quota)` | As in 5.2, on the thread-memory tree. Threads the subtree funded keep running; each node is freed when the last of its threads has exited. |

### 5.4 Compartments, entry points and types

| Syscall | Behaviour |
| --- | --- |
| `capability_compartment_t sys_compartment_create(mem_quota, initial_capabilities)` | §2.2. Slot 0 gets the new handle and the seeds follow from slot 1, uninterpreted. The bounds of the seed array set the seed count. `mem_quota` pays for the table but is not put in it. |
| `void sys_compartment_destroy(comp)` | §2.2. Succeeds whatever threads are inside and quarantines the memory; after the sweep, a thread's return into the compartment yields `ERR_COMPARTMENT_DESTROYED` to the live caller beneath. |
| `uint64_t sys_compartment_invoke(entry_point, arg, ...)` | The switcher (§3.4). Passes up to five arguments (`ca1..ca5` → `ca0..ca4`) and returns the callee's `ca0` (or a `Status` if the call was refused before entry, or `Faulted` if the callee faulted and was unwound; §3.6). |
| `Sentry sys_sentry(comp, code)` | §2.5. Returns the `EntryPoint` handle. |
| `uint64_t sys_fault_install(comp, code)` | Makes `code` (in `comp`'s own memory) `comp`'s fault handler, replacing any earlier one. Returns a `Status` (§3.6). |
| `capability_type_t sys_type_mint(record)` | §2.7. Returns the type key with both rights, or NULL. |
| `capability_type_t sys_type_derive(key, permissions)` | Re-issues `key` with a subset of its unseal (Load) and seal (Store) rights. |
| `capability_sealed_t sys_seal(key, obj)` | §2.7. Returns the `SealedObject` handle, or NULL. |
| `capability_data_t sys_unseal(key, handle)` | §2.7. Returns the payload, or NULL. |

### 5.5 Threads

| Syscall | Behaviour |
| --- | --- |
| `capability_thread_t sys_thread_create(thread_mem_quota, stack_size, entry_point, initial_arg)` | `entry_point` is an `EntryPoint` and `initial_arg` must be global. Returns a suspended handle with both rights. |
| `void sys_thread_exit(status)` | Tears down the thread and returns to the host context. The scheduler is not notified directly: it is re-dispatched and notices the exit (§2.6). |
| `uint64_t sys_thread_kill(thread)` | `Permit_Store`. §2.3. Returns a `Status`: `InvalidCapability` if not live or already ending. |
| `uint64_t sys_thread_switch(thread)` | `Permit_Load`. Parks the caller; returns 0 when resumed, or a `Status` if refused. |
| `uint64_t sys_thread_tid(thread)` | The kernel tid, or 0. |

### 5.6 Traps and interrupts

| Syscall | Behaviour |
| --- | --- |
| `uint64_t sys_trap_install(irq, handler)` | §3.6. Installs `handler`, a compartment `EntryPoint`, for `IRQ_M_TIMER` or `IRQ_M_EXT` (anything else is `InvalidAuthority`). Once each (`Busy` afterwards); a kernel, fault or local entry is `InvalidSentry`. Only `init` holds the gate. Returns a `Status`. |

The kernel's `Status` codes are defined in `types.hpp`. Only the few noted
above ever reach user space.

### 5.7 Resource manager and service interfaces

All of these are user-space compartments, reached through the switcher with
register arguments (`ca0..ca4` in, `ca0` out; `user/runtime.hpp::invoke`) or,
for wide/multi-output operations (`quota_derive`, `quota_query`, `LoadRequest`),
a request struct from `user/abi.hpp`. A derive call for a quota that does
not govern memory takes a `node_funding` `QuotaVm` to pay for the node (§2.4).
Pass a small dedicated sub-quota rather than a primary authority, since a
service may allocate against anything it is handed.

#### 5.7.1 Compartment heap allocator

The possible future design of the compartment heap allocator, subject to all of the changes and redesigns you could imagine:

```c
capability_quota_heap_t heap_quota_create(size_t initial_bytes);
capability_quota_heap_t heap_quota_derive(capability_quota_heap_t parent, size_t sub_limit_bytes, uint32_t perms);
int                     heap_quota_destroy(capability_quota_heap_t quota);

capability_t heap_allocate(capability_quota_heap_t quota, size_t size);
void         heap_free(capability_quota_heap_t quota, capability_t ptr);
```

**Not built yet.** There is no `malloc` anywhere; every compartment works
from page-granular `sys_vm_allocate` and static arrays.

#### 5.7.2 Scheduler (`sched`)

| Entry | Purpose |
| --- | --- |
| `sched.quota_derive` | Derive a child node (budget, period, class, term) from its parent's handle. Admission-checked. The class may not be more urgent than the parent's, nor the guarantee longer (§2.4). |
| `sched.quota_destroy` | Destroy a child node through its parent's handle, with everything derived under it. Threads on them stop. Refused while a fixed term runs (§2.4, §2.6). |
| `sched.quota_query` | Report a node's budget, period, class, guarantee and children, and the threads registered on it and below. The shell polls it to know a program's thread has gone. |
| `sched.thread_register` | Register a thread under a node, or move a stopped thread onto one. The thread is unregistered automatically when it exits. |
| `sched.yield` | Charge the running node and pick again. |
| `sched.block` | Sleep until woken or until an optional timeout. A wake that arrives before the block is remembered. A woken thread runs when it is next picked, so not before its node has budget. It may return spuriously, so callers loop. The caller's tid, which `wake` takes, is in `utidc` (`runtime.hpp`, `self_tid`). |
| `sched.wake` | Wake a tid. Safe to call from interrupt context. **Unprotected**: anyone holding the entry and a tid can wake that thread. |
| `sched.thread_kill` | `sys_thread_kill`, then wake the thread. From then on its `block` returns `SCHED_KILLED` without sleeping, so a callee waiting on its behalf returns, and the thread ends once back in its own code (§2.3). A stopped thread is put on the caller's node first, so this is called from thread context. |
| `sched.lock_wait` | Wait for a lock whose word showed it taken, lending the owner this thread's time meanwhile (§2.6). |
| `sched.lock_wake` | Release a lock that has waiters, handing it to the next of them. |
| `run` | The scheduler's main loop. Not published; `init` hands it to the kernel (§2.6). |

#### 5.7.3 Filesystem (`fs`)

The entries are handed to `init` in the handshake, because `fs` is up before
`naming`, and are published as `fs.<name>`:

| Entry | Purpose |
| --- | --- |
| `fs.quota_derive` | Derive a child node rooted at a path under the parent's root, with space and inode limits. It can **adopt** whatever the parent already had in that directory. |
| `fs.quota_destroy` | Destroy a node through its ADMIN handle. Cascade-unlinks the node's files and directories, and every file handle opened through the node dies. Directories shared with the parent pass to the parent. Refused while child nodes exist. |
| `fs.quota_query` | Report limits and usage. |
| `fs.create` / `fs.open` | Create a file, charged to an ADMIN node, or open one. Returns a sealed file handle, which is writable only if write access was requested through an ADMIN handle of the owner or of an ancestor. |
| `fs.read` / `fs.write` | I/O at an offset. Writing past EOF grows the file, subject to the owner's quota. Write-through; no cache. |
| `fs.close` | Close a handle. |
| `fs.mkdir` / `fs.unlink` | Create or remove a path (ADMIN). A non-empty directory, a node's root or another node's file cannot be removed. |
| `fs.list` | List a directory, including whether each entry is owned by this node, a child node or another node. |

Properties and gaps:

* Only one operation runs at a time: every entry holds a scheduler lock
  (§2.6), so a concurrent caller waits for it, lending the holder its time.
* Paths are confined, with no `..`.
* There is no rename, truncate, timestamps or permissions.
* **An unrecognised disk is auto-formatted.**
* Node and inode ownership lives in memory only (§2.4).

The on-disk format (also written by `tools/signetfs.py`) is a deliberately
simple block filesystem: a superblock, a block bitmap, and fixed-size inodes
with direct and indirect block pointers. Directories are inodes linked to
their parent; there are no directory-entry blocks.

#### 5.7.4 Drivers and other services

| Compartment | Role | Notes |
| --- | --- | --- |
| `uart` | Console output (`uart`) and non-blocking input (`uart.read`) | Input is buffered in a small ring that drops data when full. A reader passes a wake entry point, which the driver invokes **from interrupt context** when bytes arrive; the shell's wake entry then calls `sched.wake`. |
| `blk` | Sector `read` / `write` | Modern virtio-mmio only. Handles **one request at a time** through a bounce buffer in the init-owned DMA arena. Completion arrives as an interrupt that wakes the caller, which waits in `sched.block` with a timeout and falls back to polling. |
| `naming` | `publish` / `lookup` of entry points by name | Currently a fixed-size table with no unpublish and no access control. TODO! |
| `trap_mgr` | External-interrupt routing | §3.6. |
| `shell` | Console | Commands: `help`, `stats`, `demo` (class ordering and tick preemption of a non-yielding batch thread), `fsdemo` (`quota_disk` semantics), `ls`, `cat`, `write`, `append`, `mkdir`, `rm`, `df`, `run <prog> [args]`, `killtest`, `revoketest`, `faulttest` (a fault in a call is reported by the shell's default handler, and the call returns `Faulted`; §3.6), `shutdown`. Input comes from `uart.read` plus `sched.block`, woken through IRQ → `trap_mgr` → `uart` → the shell's wake entry → `sched.wake`. |

TODO: isolate DMA access. `blk` writes physical addresses into the device's
registers and descriptors, and nothing checks them, so it can point the
device at any memory. Today it is effectively part of the TCB.

The shell's `run` policy decides what a `/bin` program can get from its
manifest:

* `SYSCALL`: only `compartment_invoke`.
* `SERVICE`: `uart` and the `fs.*` entries.
* `DISK`: a capped sub-node under `/home/<prog>`.
* `FILE`: files opened under `/home`.
* A capped amount of memory, which `QUOTA_VM` hands to the program.
* A capped `quota_sched` node for its thread, which `QUOTA_SCHED` hands to the program.
* Everything else is refused.

Two programs ship: `hello` (disk sandbox, fs IPC and a `FILE` handle) and
`logo` (an animation that never yields, which makes it a preemption test).

### 5.8 `init`'s capability table (what the kernel seeds)

| Slots (`include/signetos/init.hpp`) | Contents |
| --- | --- |
| 0 | `init`'s own handle |
| `RW_SLOT_VM_QUOTA` | The root `QuotaVm` |
| `RW_SLOT_SYSCALL_BASE` … | One `EntryPoint` per syscall. `init` passes most on through manifests; `trap_install` it keeps (§3.6) |
| `RW_SLOT_THREAD_QUOTA` | The root `QuotaThreadMem` |
| `RW_SLOT_OTYPE_SCHED`, `RW_SLOT_OTYPE_DISK` | Hardware `Seal|Unseal` authorities for `OType::QuotaSched` and `OType::QuotaDisk` |
| `RW_SLOT_SCHED_RUN` | Written by `init` and read back by the kernel (§2.6) |

---

## 6. Directions under investigation

These are open research questions rather than designs. They build on the
mechanisms above, chiefly the manifest (§2.8) and compartment-minted sealed
types (§2.7). The common thread is that **every authority a compartment holds
is a capability, and every non-memory authority is a sealed handle whose
manager alone decides what it means.**

### 6.1 Auditable compartment authority

A compartment holds exactly what is in its capability table and nothing else
(§2.2). In principle, then, its authority can be enumerated and checked
against a policy before it runs and at any point while it runs.

* **Pre-launch audit.** The manifest states what an image wants, and the
  launcher builds the seed array from it. A policy checker can examine that
  array before `sys_compartment_create` and verify it against a declared
  compartmentalisation or sandboxing policy, for example: "this program may
  read `/home/<prog>`, may print to the console, may not reach the network,
  and may hold at most this much memory and CPU". Today that policy is
  hard-coded in each launcher (the shell's `run` rules, `init`'s "grant if I
  have it").
* **Policy as data.** The goal is to express sandboxing policies declaratively
  and have launchers enforce them uniformly, instead of writing ad hoc code in
  each launcher. The same policy should be able to say *why* a request was
  refused.
* **Runtime audit.** A compartment's authority can grow after launch, through
  capabilities passed in calls or stored into its memory. Questions under
  study:
  * Can that growth be tracked or bounded, for instance by forcing
    long-lived authority to arrive as sealed handles rather than raw
    capabilities?
  * Can a supervisor obtain a trustworthy inventory of what a child currently
    holds?
* **Describing a capability.** An audit needs to say what each capability
  *is*. Bounds and permissions answer that for memory. For sealed handles only
  the issuing manager knows, which suggests managers need an introspection
  entry ("describe this handle") that an auditor holding the right authority
  can call.
* **Creator visibility.** Sealing protects a compartment from its peers but
  not from its creator (§2.7). An audit model has to make that trust
  relationship explicit.

### 6.2 Fine-grained, manager-defined capabilities

Today's service handles are coarse: a `quota_disk` node grants a whole
directory subtree, and a service entry point grants every operation behind it.
The direction is for each resource manager to mint handles that name exactly
the resource and the operations a holder may use, each sealed under the
manager's own type:

| Manager | Examples of fine-grained handles |
| --- | --- |
| Filesystem | One file or directory, read-only or append-only access, a byte range, "create here but not list", time- or use-limited access. |
| Network manager | A specific remote domain or address and port, a protocol, a listening socket on one port, a bandwidth or connection quota. |
| Credential / secrets service | Use of a specific key or credential (sign, decrypt, authenticate to one domain) without ever disclosing the secret material. |
| Devices and drivers | One channel, register window or DMA buffer, rather than a whole device. |
| Services generally | One method of an interface, or a subset of its operations. |

Properties under investigation:

* **Everything is a sealed type.** The holder sees only an opaque sealed
  capability; the manager unseals it on each call and decides what it
  permits. No ambient names, paths or IDs confer authority by themselves.
* **Attenuation.** A holder should be able to derive a weaker handle (fewer
  operations, narrower scope) and pass it on without a round trip to the
  manager. Alternatively the manager offers a derive entry, as the quota
  managers do today.
* **Hardware vs. compartment-minted types.** Most of these types fit
  naturally as compartment-minted types. The more central managers might be
  given hardware object types (§2.1).
* **Manifest integration.** A manifest entry could request such a handle
  ("read `/etc/config`", "connect to `example.com:443`"), the launcher's
  policy (§6.1) would decide, and an auditor could read back exactly what
  was granted.
* **Scheduler Hierarchy** Each scheduler node can choose a policy to manage 
  its pool of threads.

---

## 7. When a thread stops inside a compartment

A thread can stop while it is inside a compartment's call:

* **killed:** `sys_thread_kill`. It ends only once it is back in its own
  code; every call it is inside runs to its return, so a kill never leaves
  a compartment half-way through anything (§2.3 has what a kill is for and
  how it plays out);
* **starved:** its `quota_sched` node is taken back and it is never scheduled
  again (§2.6). It keeps whatever state the compartment had at that
  instruction. If it holds a lock someone wants, the waiter lends it time to
  finish the critical section (`sched.lock_wait`);
* **a fault:** the compartment's own handler decides, or it is unwound
  (§3.6). This is the one case in which a compartment's code is abandoned
  mid-way, and it is that compartment's own code that faulted;
* **its compartment destroyed:** at its next resume it is unwound past every
  frame in the destroyed compartment, whose state no longer matters.

The kernel holds one rule for all of this: a killed thread ends when it
resumes its own code. There is no "trusted to finish" exemption, no cutting
of callees, and no cleanup handler, because none is needed when nothing is
cut.

What a compartment must do:

* **Return when a wait fails.** `sched.block` and `sched.lock_wait` return an
  error for a killed thread, and the compartment returns an error to its
  caller, releasing what it held on the way. That is its ordinary error
  path, which it needs for timeouts in any case.
* **Keep work on a caller's thread bounded.** A compartment that neither
  returns nor waits holds every thread that calls it, killed or not. For a
  trusted service that is a bug; an untrusted one is destroyed by whoever
  owns it, which unwinds the threads parked in it.
* **Cope with a holder that has ended anyway.** The kernel still ends a
  thread wherever it is if it has no kernel stack left to take a trap, or
  if every frame on its kernel stack is in a destroyed compartment. A lock
  whose owner has ended goes to the next waiter with `SCHED_OWNER_DEAD`;
  `blk` then drains and catches up its device queue, `fs` warns that its
  tables may be half-updated. Making `fs`'s updates safe to abandon (ordered
  writes, or a journal) is future work, and is needed for power loss anyway.

Work that nobody's call asked for -- a packet arriving, a timer, delayed
writeback -- has no caller's thread to run on and belongs on a thread the
service owns, woken from its interrupt handler. A future network stack is
built that way: the interrupt handler acknowledges and wakes, the stack's
own thread runs the protocols, and callers' threads touch only socket
buffers, under locks, as above.
