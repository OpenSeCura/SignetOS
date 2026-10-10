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
* **Required ISA extensions** (patched LLVM and QEMU, see `zyseal/setup.sh`):
  * `Zyseal`: seal/unseal instructions and permissions plus a small hardware
    object-type field. All kernel handles are hardware-sealed with it (§2.1).
  * `Zylevels1`: capability levels (global/local), used for stack-bound
    capabilities (§2.1).
* **Machine:** multi-hart QEMU `virt` with one virtio-blk disk (`disk.img`).
  There is no OpenSBI: the kernel ships a tiny M-mode stub that services the
  timer and IPI "SBI" calls.

### 0.2 Source layout

| Path | Contents |
| --- | --- |
| `kernel/` | The microkernel: boot, syscalls, the domain switcher (`sentry.cpp` + `switch.S`), compartments, quotas, threads, VM and frame allocator, revocation, traps, sealing, the outbound capability check (`inspect.cpp`) |
| `include/signetos/` | Kernel headers (`types.hpp` holds `OType`, `Status`, perms) |
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
| **Single privilege level**: everything runs at one CPU privilege level; only the kernel holds ASR | Everything runs in S-mode with permissive page-table entries; the only thing separating compartments is CHERI. Only kernel entry points run with ASR (§2.5). |
| **CHERI-enforced isolation** | Bounds, permissions, sealing and tags are the only isolation mechanism. |
| **Thread migration model**: threads are not owned by compartments and migrate through a domain switcher | `sys_compartment_invoke` is the switcher (§3.4). A thread's kernel stack records the calls and traps it is inside; nothing records which compartments (§2.2, Lifecycle). |
| **Capability system call interface**: syscalls are cross-compartment invocations into the kernel | Kernel syscalls are entry points (§2.5) invoked through the *same* switcher gate as any other compartment call. That gate is the only hardware sentry the kernel gives a compartment. |
| **Zero-kernel-heap architecture** | There is no `kmalloc`. Every kernel object (quota node, compartment, thread, entry page, revocation backlog page) is whole pages billed to the requester's quota (§4.3); the only static roots live in `.bss`. |

### 1.2 The system as it runs today

```
 hardware  ──►  kernel (S-mode, ASR)  ──►  init (embedded)
                                             │  creates the core services
                                             │  (drivers, loader, fs, naming,
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
* **The scheduler is strict-priority round-robin** with per-node budgets and
  lazy replenishment. It has no policy delegates, locks or bandwidth
  inheritance (§2.6).
* **Revocation sweeps run only under memory pressure.** Freed memory is
  quarantined and stays mapped until a sweep (§4.2).
* **An unbound synchronous fault halts the whole machine** (§3.6).

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
* the revocation backlog.

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

| `OType` (`types.hpp`) | C type name | What it is |
| --- | --- | --- |
| `Unsealed` | `capability_t`, `capability_data_t`, `capability_exec_t` | Ordinary memory capabilities. |
| `Sentry` | — | A hardware sentry (jumpable). The only one the kernel hands out is the switcher gate; compartments can make their own over their own code (§2.5). |
| `QuotaVm` | `capability_quota_vm_t` | Hierarchical virtual-memory budget (§2.4). |
| `QuotaThreadMem` | `capability_quota_thread_mem_t` | Budget for thread stacks and thread state (§2.4). |
| `QuotaHeap` | — | Reserved for the heap allocator (§5.7.1), which does not exist yet. |
| `QuotaSched` | — | Scheduler CPU-bandwidth quotas (§2.4, §2.6). |
| `QuotaDisk` | — | Filesystem disk quotas and open-file handles (§2.4, §5.7.3). |
| `Compartment` | `capability_compartment_t` | Handle to a compartment (§2.2). |
| `Thread` | `capability_thread_t` | Handle to a thread; Load → switch to it, Store → kill it. |
| `Revoker` | `capability_revoker_t` | Authority over a VA range, used to register it for revocation. |
| `TypeKey` | `capability_type_t` | Compartment-minted type key (§2.7). |
| `SealedObject` | `capability_sealed_t` | Compartment-sealed object (§2.7). |
| `EntryPoint` | `Sentry` | Sealed pointer to an entry record describing a compartment or kernel entry point (§2.5). |
| `Trap` | — | Per-vector trap authority minted at boot (§3.6). |

**Permission convention on handles:** `Permit_Load` is the *operational*
right (use it) and `Permit_Store` the *administrative* right (derive from it,
destroy it, kill it). Quotas, threads, revokers and type keys all follow it.

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
ranges, the chain of entry pages, the UID and liveness flags. It does not
record which threads are inside it, or how many. The kernel keeps no global
list of compartments, or of threads.

TODO: a capability table is currently 1 page!!!! That's not really very useful right now.

#### Compartment UID

A UID is a 64-bit value from a monotonic counter, assigned at creation and
never reused. The trap table tags each binding with the owner's UID, so a
stale binding can never be attributed to a later compartment that occupies the
same memory. The UID conveys no authority.

#### Capability table layout

| Slot | Contents |
| --- | --- |
| 0 | The compartment's own handle. |
| 1 | The funding `QuotaVm` handle. |
| seeds | The `initial_capabilities` array, in order, exactly as the creator supplied it. By convention seed *i* is manifest entry *i* (§2.8). |
| after the seeds | Free for the compartment's own use. |

The whole table is one writable region reached through `cgp`. Slot 0 is not
write-protected yet.

#### Ownership tracking

The memory a compartment owns is recorded on a chain of **range pages**,
billed to the funding quota. A second chain of **entry pages** holds entry
records (§2.5). Lookups are linear scans, which is a known TODO, and the
chains only grow while the compartment lives.

#### Lifecycle

* `sys_compartment_create(quota, seeds)` fills slot 0, slot 1 and the seeds,
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
    **quarantining** them (§4.2), and refunds the funding quota.
  * The call returns nothing, so failures are silent. A stale handle is
    refused because the compartment is no longer live.

Any sealing types a compartment minted die with the memory that holds their
records (§2.7).

### 2.3 Threads

A thread is an execution context: registers, PC and stack. Threads do not
belong to compartments. They are funded from a `QuotaThreadMem`, scheduled by
the user-space scheduler under a `quota_sched` node, and migrate freely
between compartments.

| Element | Description |
| --- | --- |
| Descriptor | The thread's descriptor (saved registers and bookkeeping, reached through the thread handle) sits at the front of its allocation; the rest is a small **kernel return stack** that holds only switcher and trap frames. Syscall bodies run on a slice of the **caller's own stack**, not on the kernel stack (§3.4). Nesting depth is bounded by this stack; when it runs out, the call is refused with `NoKernelStack`. |
| Thread stack | Allocated from the same quota and made local (§2.1). When the thread migrates, the switcher narrows the stack so the callee sees only the unused part below the current stack pointer. |
| TLS | Not implemented yet.|
| Billing | State and stack are debited from the `QuotaThreadMem` and refunded at teardown. |
| Identity | A kernel tid, never reused, exposed by `sys_thread_tid`. The scheduler keys its tables by it. |
| Hierarchical CPU bandwidth | A parent derives a child `quota_sched`, creates the thread and registers it under that quota (§2.6, §3.3). When the child quota is destroyed, its bandwidth returns to the parent node. |
| Exit | `sys_thread_exit` quarantines its memory, refunds the quota, and **always returns to the host context**. The host loop then re-dispatches the scheduler (§2.6). |
| Kill | `sys_thread_kill`. A thread that never ran is torn down at once. Otherwise it is marked, and the kernel acts on the mark each time it resumes compartment code on it (return from a call, end of a trap) (`unwind.hpp`, KILLED THREADS). See the table below. `sched.thread_kill` wakes the thread and keeps it from sleeping again, so a kill takes effect within a tick of its CPU time. |

Code about to resume on a killed thread (trap handlers included):

| Code | Result |
| --- | --- |
| The thread's original compartment (inside no call) | The thread ends. |
| The kernel, or a compartment trusted to finish | Runs on; the call completes. |
| Any other compartment | Cut: its frame is skipped and its caller gets `Status::Killed`. |

* **Trusted to finish**: `sys_compartment_trust_to_finish(comp)` sets `FLAG_TRUSTED_TO_FINISH`. `init` sets it on uart, loader, blk, fs, naming, sched and trap_mgr. The switcher copies it into the call's `ReturnFrame::flags`, and the trap dispatcher into the handler's `TrapFrame::flags` (`ENTRY_FLAG_TRUSTED_TO_FINISH`); kernel entries always get it. Trusted code must never wait forever.
* **No cleanup runs on a killed thread.** A compartment that is not trusted to finish must cope with a call being cut at any point, e.g. by recording the owner's tid in its locks and repairing state when the owner is found dead.

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
   authority (derive children, destroy).
4. **Immutable partitions.** Budgets are fixed at derivation. There is no
   resize and no renegotiation (§3.5).
5. **No reparenting.** Destroying a node never moves its children to another
   parent. What else it does is the manager's policy. The kernel's memory trees **close**:
   a destroyed node and every node beneath it refuse new charges and
   derives, every unused byte in the subtree returns to the destroyed node's
   parent at once, a closed node keeps only what is outstanding and passes
   every later refund straight to its first live ancestor, and it is freed
   when nothing is outstanding, because memory can only come back through
   the revoker. `sched` is to
   **cascade**: destroying a node kills the threads registered under it and
   its subtree, because bandwidth is a promise the parent needs back at once
   and stopping a thread is free. (Not yet implemented: today `sched` refuses
   while threads or children remain.)

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
  bounded by the parent's budget. Both come back when the node is freed, and
  its page is quarantined.
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
| `quota_sched` | scheduler (user space) | `OType::QuotaSched` | Recurring CPU bandwidth (C per T). |
| `quota_disk` | filesystem (user space) | `OType::QuotaDisk` | Disk space and inodes. |

When the dimension is not memory (`quota_sched`, `quota_disk`), the caller
passes a `node_funding` `QuotaVm`. The manager allocates the node page against
it with `sys_vm_allocate(manager_comp, node_funding, …)`, so the bytes are
debited from the caller while the mapping and its capability stay with the
manager. Destroying the funding quota while nodes are live does not take them
away: the quota closes and is freed once the manager releases its pages.

##### `quota_sched` node

A node holds a budget and period (C/T), the bandwidth delegated to its
children, a priority class, an optional deadline, a policy, the remaining
budget for the current period, and the count of registered threads. The root
covers 100 % of CPU bandwidth and is funded from the scheduler's own quota.
Temporal conservation (`C_c/T_c ≤ (C_p − D_p)/T_p`) is enforced at derive
time.

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
table, the owning compartment, flags, and the minimum stack.

* `sys_sentry(comp, code)` requires `code` to lie in executable memory owned
  by `comp`. It writes a record on `comp`'s entry pages (billed to `comp`) and
  returns a sealed `EntryPoint` handle bounded to the record. The handle is
  not jumpable: it is a token presented to the switcher.
* The kernel's own system calls are records too, flagged `TRUSTED`. The
  kernel gives a compartment **one** hardware sentry, the switcher gate, and
  every domain crossing goes through it, kernel or not (§2.9).
* `user/runtime.hpp::mint_entry` is the usual way to make one: it re-bases the
  compartment's PCC onto a function and calls `sys_sentry`.

Records are what the *switcher* accepts. They are not the only way code can
be shared. Nothing stops a compartment from making an ordinary CHERI hardware
sentry over its own code and handing it to a peer; the outbound check
(§3.4) explicitly allows such sentries as call arguments. Jumping to one is
not a domain crossing, though:

* the code runs on the caller's stack, with the caller's capability table;
* there is no scrubbing and no return frame;
* the target can still reach whatever its own code capability covers, such as
  its GOT and through it its globals.

This makes a raw sentry a deliberate, unprotected form of sharing (shared
library code, or trust between cooperating compartments), not an entry
point. Whether to restrict it, for example by forbidding compartment-made
sentries in arguments, is an open question.

Everything the switcher does *with* an entry is described in §3.4.

### 2.6 The Scheduler Compartment

Scheduling lives entirely in user space (`external/services/sched.cpp`). The
kernel keeps **no** scheduling state and never picks a thread. It provides
exactly two things: `sys_thread_switch`, and a timer trap that the scheduler
binds.

1. **Sealing authority.** The scheduler seals and opens `quota_sched`
   handles.
2. **Hardware preemption.** The scheduler binds the timer interrupt with
   `sys_trap_bind`. The kernel owns the tick period and re-arms the timer.
3. **Run queues and bandwidth tracking in user memory**, debited with no
   syscalls.
4. **Verified policy delegates.** A sub-quota selects a vetted policy engine
   (`EDF`, `FIFO`, `WORK_STEALING`, `ROUND_ROBIN`) that orders threads within
   its subtree.
5. **Exhaustion and replenishment.** A thread that runs out of budget waits
   for the next period without affecting its siblings.
6. **Dispatch** via `sys_thread_switch`, including from inside the tick
   handler. A preempted thread then parks in its trap handler until it is
   picked again.
7. **Allowance reclaim.** Destroying a sub-quota returns its bandwidth to the
   parent.
8. **Bandwidth inheritance.** A thread blocked on a lock held by a depleted
   thread lends that thread its budget.
9. **Contended synchronisation.** Uncontended locks are local atomics;
   contention calls `sched_lock_wait`; waiters on a dead owner's lock wake
   with `ERR_LOCK_OWNER_DEAD`.

**Current policy:** strict priority classes (`RT`, then `INTERACTIVE`, then
`BATCH`), round-robin across nodes within a class, and a node is skipped once
its budget for the current period is spent. Admission is checked at derive
time. When nothing is runnable the scheduler spins instead of waiting for an
interrupt.

**Not built yet:**

* run queues: tables are static and every pick is a linear scan;
* a replenishment queue: replenishment is computed lazily at pick time;
* `WORK_STEALING`: RR, FIFO and EDF exist as built-in intra-node orderings,
  and custom policy registration cannot be reached yet;
* bandwidth inheritance;
* locks of any kind: blocking is `block` plus `wake(tid)`, and **anyone may
  wake any tid**.

**Run loop:** `init` hands the scheduler's `run` entry point back to the
kernel. After `init` exits, the kernel creates a thread on that entry and
**re-dispatches it every time the running thread exits**. That is how the
scheduler learns about exits: it is resumed, scans its tables, and notices
the dead thread. When no registered threads remain, the run loop returns and
the kernel powers the machine off.

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
   of the type become unopenable at once. Sweeps currently run only under
   memory pressure (§4.2), so on an idle machine a freed type stays openable.
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
and BSS, and the location of the manifest.

* The trampoline (`user/entry.S`) sets up `cgp` and globals, then calls
  `compartment_main(Capability arg)`.
* Installing an image copies it and resolves its capability relocations;
  targets in read-only data get read-only capabilities.
* W^X: the PCC covers text, read-only data, relocations and GOT, page-padded
  so the bounds are exact. `.data` and `.bss` lie outside the PCC and are
  never executable.

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
  * `IRQ` / `EXC`: trap authorities.
  * `QUOTA_THREAD`: a thread-memory quota.
  * `ROOT`: one of the system's root quotas.
  * `OTYPE`: a hardware sealing authority (`OType::QuotaSched`, `OType::QuotaDisk`).

  Only `init` can meet the hardware and root kinds.
* `MANIFEST_REQUIRED` tells the launcher not to start the image without that
  entry. Any other unmet entry becomes a null slot, and by design the program
  cannot tell "refused" from "unavailable".
* `SIGNETOS_MANIFEST(...)` is an X-macro that emits both the table and the
  matching `SLOT_*` constants, so the two cannot disagree.

**The manifest is a request, never an authority.** It is just bytes in a
file. The launcher (`init` for services, the shell's `run` for programs)
applies its own policy to every entry and derives every grant from what it
holds itself.

#### The loader (`boot/loader.cpp`)

Every compartment creation goes through the loader, which holds no authority
of its own. Given a VM quota, a seed array and an image, it:

1. checks the manifest is well formed and matches the seeds;
2. creates the compartment;
3. installs the image into memory allocated from the same quota;
4. mints the entry point;
5. writes the handles back into the request.

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
| 3 | `loader` | The syscalls it needs and `uart` printing. It gets no quotas or resources of its own and is used for every later step. |
| 4 | `blk` | The virtio MMIO window and a physically contiguous **DMA arena allocated by init**. Handshake passes the arena's physical address and returns `read`/`write`/IRQ entries. |
| 5 | `fs` | Memory syscalls, `OType::QuotaDisk`, `uart`, `blk.read`/`blk.write`, and memory for its tables sized to the disk. It mounts the disk and creates the root `quota_disk`. |
| 6 | `naming` | Once it is up, init publishes `uart`, `loader` and the `fs.*` entries. |
| 7 | `sched` | `OType::QuotaSched` and the timer trap authority. Afterwards init tells `blk` how to reach the scheduler so it can sleep instead of polling. |
| 8 | `trap_mgr` | The PLIC window, the external-interrupt authority and the exception authorities it asks for. Init routes the UART and blk interrupt sources to their drivers; routing is init-only. |
| 9 | `shell` | Per its manifest: a thread-memory quota, `/home` as an ADMIN `quota_disk` (adopting what is already there), `/bin` as a read-only OP view, and the root quotas it asks for. Init then creates **the only thread it ever creates**: the shell's, with the shell's ADMIN `quota_sched` (`INTERACTIVE`) as its argument, registered with the scheduler. |
| 10 | — | Hand `sched.run` to the kernel, scrub its own syscall entries, and exit. |

### 3.2 Creating and loading a new compartment

The `loader` compartment parses binaries and constructs compartments; the
launcher decides what the new compartment gets.

```
Launcher (init / shell)                 Loader                              Kernel
  |-- read image, parse .manifest         |                                   |
  |-- build seeds[] by policy             |                                   |
  |   (sys_quota_vm_derive, fs.quota_derive, naming.lookup, ...)              |
  |-- sys_compartment_invoke(loader, LoadRequest{vm_quota, seeds, image}) -->|
  |                                       |-- sys_compartment_create(q, seeds)->|
  |                                       |<-- comp ---------------------------|
  |                                       |-- sys_vm_allocate(comp, q, size)-->|
  |                                       |<-- zeroed RW memory --------------|
  |                                       |   [copy image, resolve cap_relocs,|
  |                                       |    derive PCC view: W^X]          |
  |                                       |-- sys_sentry(comp, pcc) --------->|
  |                                       |<-- EntryPoint --------------------|
  |<-- (out_comp, out_sentry in request)--|                                   |
```

1. **Derive the VM quota.** The launcher derives a quota from its own for the
   memory the manifest asks for, capped by its policy.
2. **Build the seeds.** For each manifest entry the launcher derives or looks
   up the grant (sub-quotas, disk nodes, service entry points) or leaves a
   null.
3. **Request loading.** The launcher invokes the loader.
4. **Create the compartment.** The compartment's pages are billed to the new
   quota (§2.2).
5. **Allocate and install.** The loader allocates zeroed memory owned by the
   new compartment, copies the image, resolves relocations and derives the
   W^X views (§2.8).
6. **Mint the entry.** `sys_sentry` returns the `EntryPoint`.
7. **Return.** The handles come back in the request struct. The switcher
   scrubs the loader's temporaries from the stack on return.

### 3.3 Executing a compartment and thread scheduling

Once loaded, a compartment is passive; a thread has to enter it.

#### A. Starting an independent program (the shell's `run`)

1. Derive a `quota_sched` for the program under the shell's own node.
2. `sys_thread_create` on the program's entry, from the shell's thread-memory
   quota, which returns a suspended thread.
3. Register the thread with the scheduler under the new quota.
4. The scheduler dispatches the thread with `sys_thread_switch` when its
   class and budget allow.

It does not get its own `quota_sched` right now: the shell keeps the
ADMIN handle so it can tear the node down. A program therefore cannot yet
sub-delegate bandwidth to threads of its own. Once TLS exists (§2.3), a thread
would keep its quota there for that purpose.

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

**Outbound capability policy (`kernel/inspect.cpp`):** every capability
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
* Freed pages are quarantined rather than reused. Quota is refunded
  immediately, but physical memory only comes back after a sweep (§4.2).

### 3.6 Hardware trap and interrupt handling

1. **Authority distribution:** at boot the kernel mints one `OType::Trap`
   authority per exception code and interrupt number into `init`'s table. The
   kernel keeps its own IPI vector. `init` passes the authorities on according
   to manifests: the timer to `sched`, and the external interrupt and the
   page/CHERI fault codes to `trap_mgr`.
2. **Handler registration:** `sys_trap_bind(comp, auth, EntryPoint)` requires
   the handler to be owned by `comp`. The kernel keeps a static trap table
   under a seqlock, and every bind is synchronised to all harts by IPI.
   Bindings are purged when their compartment is destroyed.
3. **Trap occurrence (currently!):**
   * Internal events (demand-paging and CoW faults) are meant to be handled
     silently by the kernel. None exist yet (§3.7), so every trap is either
     bound or fatal.
   * A bound trap pushes a trap frame on the interrupted thread's kernel
     stack. The handler then runs **on the interrupted thread's own, narrowed
     stack**, with the cause and fault information as arguments.
   * Interrupt handlers run with interrupts masked. Exception handlers inherit
     the interrupted state when there is stack room. The handler's stack
     region is scrubbed on return.
   * The kernel re-arms the tick before each timer delivery.
   * **An unbound synchronous exception, including a CHERI fault in a
     compartment, is reported and halts the whole machine.** A fault inside
     kernel code always halts. A thread with no kernel-stack room for the
     frame is ended instead.
4. **Resolution:** the handler returns through the switcher and the thread
   resumes. The scheduler's handler may instead `sys_thread_switch` away, and
   the thread then stays parked in its handler.
5. **Deregistration:** `sys_trap_unbind` exists, but nothing calls it yet.

**The trap manager (`external/services/trap_mgr.cpp`):**

* Owns the PLIC and binds the external interrupt, for the **boot hart only**.
* Keeps a small static routing table from sources to driver handlers. `init`
  fills it and the routing entry is not published. There is no unroute.
* On an interrupt it claims the source, invokes each routed handler, and
  completes the source.
* Holds the exception authorities but **never binds them**. There is no fault
  reporter yet, hence the machine-halt behaviour above.

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
sched.quota_destroy(prog_sched);         // refused while threads are registered
sys_vm_deallocate(image & buffers);
sys_quota_vm_destroy(prog_vm_quota);     // closes; freed once nothing it funded remains
```

| Step | Behaviour |
| --- | --- |
| Compartment destruction | Every owned range is **quarantined** (still mapped, never reissued) and reclaimed by the next sweep. The compartment's own pages are refunded to its funding quota. |
| Resident threads | Destroy does not wait for them: once the sweep has run, a thread returning into the destroyed compartment is unwound to its nearest live caller, which gets `ERR_COMPARTMENT_DESTROYED` (§2.2). The shell still **waits for exit** before tearing down, by polling `sched.quota_destroy` until it succeeds, because the scheduler quota cannot go while the thread is registered. There is no join or timeout. A running program can be killed (§2.3). |
| `sys_quota_vm_destroy` | Closes the quota and its whole subtree and refunds every unused byte in it at once. Each node is freed, and the rest refunded, when everything it funded has been released. Fails only for a bad or already-closed handle or missing `Permit_Store`. |
| `sched.quota_destroy` | Returns the bandwidth to the parent and releases the node page to its funding grant. Today refused while threads or child nodes remain; the intended policy is to cascade instead (§2.6). |
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
| 4. Control-flow integrity | Switcher-mediated entry happens only through `EntryPoint` records. Raw hardware sentries that compartments make over their own code bypass the switcher and carry none of these guarantees (§2.5). |
| 5. Deterministic unwinding | Return frames live on the thread's trusted stack. The return path validates the frame chain and kills the thread on a mismatch. |


### 4.2 Capability sharing and memory revocation

| Model | Description |
| --- | --- |
| 1. Ephemeral borrowing (local capabilities) | A caller lends a buffer by passing a local capability in a register argument. The callee cannot store it outside a stack, and access ends with the call, so no sweep is needed. |
| 2. Persistent sharing via sealed handles | The owner seals handles under its hardware `OType` (§2.1) or a compartment-minted type (§2.7) and hands out handles that only it can open. Used for `fs` file handles and for both services' quota handles. |
| 3. Direct global sharing with quarantine + revocation | Raw global capabilities shared across compartments require the memory to be revoked before it is reused. The mechanism is complete, but the **sweep trigger policy is missing** (see below). |

**Revocation (`kernel/revoke.cpp`, `kernel/vm.cpp`):** (Early, janky and very much an area of active thought and design)

### 4.3 Architectural invariants

| Invariant | Notes |
| --- | --- |
| Capabilities are the sole source of authority; the MMU is never used for access control, only for backing, demand paging and CoW write detection | Page permissions are permissive everywhere. Demand paging and CoW write detection do not exist yet, so the MMU currently does *only* backing. |
| Accessibility invariant: never unmap under a valid capability | Quarantine keeps freed pages mapped until the sweep has cleared every tag. |
| Sealing type invariant: a compartment cannot open or forge an authority without holding the authority for its type | Kernel authorities and service quotas (`QuotaSched`, `QuotaDisk`) use hardware types. Compartment-minted objects use software types (§2.7), whose identity is a hardware tag and cannot be made by writing memory. |
| Compartment UID permanence | UIDs are never reused, so UID-tagged records can never be misattributed. |
| Type identity (address of the type record) | Subject to the sweep caveat in §2.7. |
| Deterministic quotas and write guarantees | All memory is backed at allocation time; nothing is lazy, so nothing can fail later. |
| Immutable quota partitions | Quotas cannot be resized after derivation (§3.5). |
| Self-funding metadata | Compartments, threads, kernel quota nodes, entry pages, range pages, revocation backlog pages, scheduler nodes and fs nodes are all billed to the requester. The exceptions are page tables, which come from the frame pool, are never freed and are not charged, and each service's own static tables, which the service pays for from its own quota. |

### 4.4 Multi-hart status

The kernel is written with SMP in mind:

* per-hart stacks and CPU state;
* spinlocks on shared structures;
* IPI-based synchronisation of trap-table updates;
* atomic claiming of threads in `kill` and dispatch.

**Today, though, every thread runs on the boot hart; the secondary harts are
brought up and park.**

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
| `capability_t sys_vm_allocate(comp, mem_quota, size, flags)` | Debits `mem_quota` and records the range as owned by `comp`. Returns a read/write capability bounded to the allocation, with `StoreLocal` stripped. Memory is always zeroed; **`flags` are ignored for now**. |
| `void sys_vm_deallocate(comp, mem_quota, mem_capability)` | `mem_quota` must be the quota that funded the range. Refunds and **quarantines** the memory (§4.2). |
| `capability_t sys_cow(comp, mem_quota, src_memory, len)` | Debits `len` up front. Currently an **eager copy** that keeps tags (§3.7). |
| `capability_revoker_t sys_revoke_create(comp, mem_cap)` | Creates a `Revoker` over `mem_cap`'s bounds, which must lie within a range `comp` owns. |
| `capability_revoker_t sys_revoke_derive(parent_revoker, sub_cap, permissions)` | Creates a child authority within the parent's range. |
| `uint64_t sys_revoke_register(revoker_cap, mem_cap, mem_quota)` | Records a range within the revoker's bounds for the next sweep, funded by `mem_quota`. Returns the target epoch, or 0 if refused. |
| `uint64_t sys_revoke_query(void)` | Highest completed epoch (§4.2). |

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
| `capability_compartment_t sys_compartment_create(mem_quota, initial_capabilities)` | §2.2. The bounds of the seed array set the seed count. |
| `void sys_compartment_destroy(comp)` | §2.2. Succeeds whatever threads are inside and quarantines the memory; after the sweep, a thread's return into the compartment yields `ERR_COMPARTMENT_DESTROYED` to the live caller beneath. |
| `uint64_t sys_compartment_invoke(entry_point, arg, ...)` | The switcher (§3.4). Passes up to five arguments (`ca1..ca5` → `ca0..ca4`) and returns the callee's `ca0` (or a `Status` if the call was refused before entry). |
| `Sentry sys_sentry(comp, code)` | §2.5. |
| `uint64_t sys_compartment_trust_to_finish(comp)` | §2.3. Permanent. Returns a `Status`. |
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
| `void sys_trap_bind(comp, auth_cap, target)` | `auth_cap` is a `Trap` authority carrying `Permit_Load`. `target` is an `EntryPoint` owned by `comp`; a kernel entry is refused. Replaces any existing binding for the vector. |
| `void sys_trap_unbind(comp, auth_cap)` | Not used yet. |

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
| `sched.quota_derive` | Derive a child node (budget, period, class, policy, optional deadline) from a parent ADMIN handle. Admission-checked. Returns an ADMIN or an OP handle depending on the requested rights. |
| `sched.quota_destroy` | Destroy a node through its ADMIN handle. Refused while it has children or registered threads; the intended policy is to cascade instead (§2.6). The shell uses this as a stand-in for join. |
| `sched.thread_register` | Register a thread under a node. The thread is unregistered automatically when it exits. |
| `sched.yield` | Charge the running node and pick again. |
| `sched.block` | Sleep until woken or until an optional timeout. A wake that arrives before the block is remembered. It may return spuriously, so callers loop. |
| `sched.wake` | Wake a tid. Safe to call from interrupt context. **Unprotected**: anyone holding the entry and a tid can wake that thread. |
| `sched.thread_kill` | `sys_thread_kill`, then wake the thread. From then on its `block` returns `SCHED_KILLED` without sleeping. Safe to call from interrupt context. |
| `sched.self` | Return the caller's tid, for use with `wake`. |
| `sched.policy_register` | Register a custom policy engine. Not reachable yet (§2.6). |
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

* Only one operation runs at a time; concurrent callers get `FS_BUSY`, and a
  few read-only entries are not yet guarded.
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
| `loader` | Compartment construction | §2.8. |
| `shell` | Console | Commands: `help`, `stats`, `demo` (class ordering and tick preemption of a non-yielding batch thread), `fsdemo` (`quota_disk` semantics), `ls`, `cat`, `write`, `append`, `mkdir`, `rm`, `df`, `run <prog> [args]`, `shutdown`. Input comes from `uart.read` plus `sched.block`, woken through IRQ → `trap_mgr` → `uart` → the shell's wake entry → `sched.wake`. |

The shell's `run` policy decides what a `/bin` program can get from its
manifest:

* `SYSCALL`: only `compartment_invoke`.
* `SERVICE`: `uart` and the `fs.*` entries.
* `DISK`: a capped sub-node under `/home/<prog>`.
* `FILE`: files opened under `/home`.
* A capped amount of memory.
* Everything else is refused.

Two programs ship: `hello` (disk sandbox, fs IPC and a `FILE` handle) and
`logo` (an animation that never yields, which makes it a preemption test).

### 5.8 `init`'s capability table (what the kernel seeds)

| Slots (`include/signetos/init.hpp`) | Contents |
| --- | --- |
| 0, 1 | `init`'s own handle; the root `QuotaVm` |
| `RW_SLOT_SYSCALL_BASE` … | One `EntryPoint` per syscall |
| `RW_SLOT_IRQ_BASE` … | The interrupt `Trap` authorities |
| `RW_SLOT_EXC_BASE` … | The exception `Trap` authorities |
| `RW_SLOT_THREAD_QUOTA` | The root `QuotaThreadMem` |
| `RW_SLOT_OTYPE_SCHED`, `RW_SLOT_OTYPE_DISK` | Hardware `Seal|Unseal` authorities for `OType::QuotaSched` and `OType::QuotaDisk` |
| `RW_SLOT_SCHED_RUN` | Written by `init` and read back by the kernel (§2.6) |

`init`'s entry argument is the boot manifest.

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

---
