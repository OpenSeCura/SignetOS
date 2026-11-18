# SignetOS Core Design

SignetOS is a single-address-space, single-privilege-level capability microkernel
for CHERI architectures. Isolation is enforced by capabilities alone; the MMU is
used for address translation, never for protection.

SignetOS is built around the following core idea: 
access to objects is controlled by sealed opaque handles, those objects are funded by hierarchical quotas and managed by their respective resource manager compartment.

## Threat model

We assume correct, formally verified hardware. The kernel and the few
user-space compartments that hold system-wide authority (`init` while it boots
the system, the scheduler and the resource managers) are trusted to be correct,
and are kept small so that they can be formally verified in future. Every other
compartment is untrusted and assumed malicious: it
runs arbitrary code, alone or in collusion with others, and will try to
escalate its privileges by forging, widening or reusing stale capabilities, to
deny service by spinning, holding locks or never returning, to exhaust memory
or a manager's own state, and to leak, corrupt or keep hold of the shared
objects and buffers it can reach. The design must contain it regardless: it can
act only through the handles it holds and consume only what its quotas fund,
and a driver can misuse its own device but must not be able to compromise the
integrity of any other compartment (§8). No compartment is protected from physical attacks.
There inherently exists an initial trust relationship between a parent compartment and its
children since the parent specifies what should be created.

## Design pillars

Everything a compartment can do beyond accessing its own memory comes from
sealed capabilities. Access to an object, such as a compartment, thread, compartment entry
point, file or socket, is granted by a **sealed handle**: an opaque capability
its holder cannot dereference or alter, only pass on or present to the object's
manager along with a request to perform a desired operation. 
Every object which is pointed to by a sealed handle is funded by **quotas**, which themselves are a sealed handles,
to nodes in a hierarchical budget of a resource such as virtual memory, thread memory, CPU time, storage
or network.

A compartment asks a **resource manager** for an object and presents a quota to
pay for it. The manager charges the quota, creates the object and returns a
handle to it, then serves every later request that presents the handle,
checking the rights it carries, until the object is destroyed and its budget
goes back to the quota. Only a manager can seal and unseal its own handles, so
nobody else can forge or open them.

A quota can also be split monotonically: its holder can derive a smaller one to hand on,
never more quota than it was given. 

A compartment can act on exactly the objects it holds handles to, 
and consume no more than its quotas allow (§2, §6, §10).

The resource managers divide between the kernel and user space (§2.1):

| Kernel object handle | Manager | Funded by |
| --- | --- | --- |
| **Entry point** | kernel | the exporting compartment's VM quota (none for syscall gates) |
| **Compartment** | kernel | VM quota |
| **Thread** | kernel | thread-memory quota, plus a CPU quota (`sched`) to run on |

| User-space object handle | Manager | Funded by |
| --- | --- | --- |
| **File** | filesystem (`fs`) | disk quota and memory quota |
| **Socket** | network service (`net`) | network quota and memory quota |
| **Allocation** | heap allocator | heap quota (the heap was created with a VM quota) |
| **Type key** | sealer (`sealer`) | lives in the owner's own memory |
| **Sealed object** | sealer (`sealer`) | lives in the owner's own memory |

The kernel manages only the types its own mechanisms, such as the switcher and
virtual memory, depend on. Every manager needs the sealing authority for its
types; the kernel holds the root they all derive from, gives each user-space
manager its authority at boot, and never learns what those handles mean.
For each sealing authority handed to another compartment, the kernel loses the capability needed to
seal or unseal such capabilities to ensure that the authority lies exclusively with the relevant compartment.

Quota nodes are objects too, each paid for by the quota of whoever derived it in the case of memory quota nodes,
or by a separate memory quota node provided at creation time to obtain the memory needed for the node.
Thus the only unpaid things are the boot-time roots. The kernel keeps no heap, 
and no manager needs to spend its own memory on a client, avoiding potential resource exhaustion attacks.

---

## 1. Architecture

| Principle | Design |
| --- | --- |
| **Single virtual address space** | One address space and one page table shared by everything; nothing is remapped on switches or calls. |
| **Single privilege level** | One CPU privilege level with permissive page-table entries; only kernel syscall entry points hold system-register access (ASR). |
| **Migrating threads** | Threads do not belong to compartments; they cross domains through the switcher, with a small trusted kernel stack recording active calls and traps. |
| **Capability syscalls** | Kernel syscalls are entry points invoked through the *same* switcher gate as any cross-compartment call. Thus the kernel acts as another compartment. |
| **Quarantine** | Freed pages stay mapped and in quarantine until a sweep clears all tags on capabilities pointing to them. Additionally sub-page memory which is mapped as revocable may be added into a quarantine to be included in such sweeps. |

**Bootstrap.** At boot, the kernel creates one compartment (`init`) seeded with
the root quotas, all syscall gates, device windows, and service sealing
authorities. `init` starts the core services (console, block driver, filesystem,
naming, sealing service, scheduler, shell), grants each only
what its manifest requests, hands the scheduler's dispatch entry to the kernel,
clears its own table, and exits.

---

## 2. Capabilities and Sealing

### 2.1 Sealed handle types

Each type is managed by a resource manager, which alone can seal and unseal it.
`init` hands each user-space manager its sealing authority at boot; the kernel
keeps the rest. A handle's rights are fixed when its manager creates it: a holder
cannot weaken a handle itself, since a sealed capability cannot be modified, so
a weaker handle has to come from the manager.

**Kernel object handles** name an object the kernel manages.

| Handle | Rights | Held by |
| --- | --- | --- |
| **Entry point** | Invoke one syscall, or one entry a compartment exported over its own code (§4). | entry points may be held by any compartment (depending on policies). |
| **Compartment** | Identify it to the syscalls that act on it: allocate its memory, export entry points, install its fault handler, revoke its sub-ranges (§3), destroy it. All but destroy need `Store`. Kernel does not track compartments. | the compartment itself (slot 0, with `Store`) and its launcher (without `Store`: it can only destroy it) |
| **Thread** | Name it to the syscalls that act on it: switch to it, kill it. | its creator; the scheduler, once registered |

**User-space object handles** name an object a user-space manager keeps. A
handle that is passed on, as a file or a socket is, splits its rights: `Load`
carries the user right and `Store` the administrative right, so it can be handed
out with the user right alone. A heap allocation comes as a sealed handle, the
authority over it, with a plain payload, the memory itself, so its handle needs
no split. A sealed object has no administrator, so its handle carries no rights
of its own: whoever unseals it gets the payload with the permissions it was
sealed with, and the rights over its type are in the type key, which the sealer
can re-issue with fewer of them.

| Handle | User right | Administrative right | Held by |
| --- | --- | --- | --- |
| **File** (filesystem) | Read it. | Write it, close it. | whoever opened it or was passed it |
| **Socket** (network service) | Send and receive. | Close it. | whoever opened it or was passed it |
| **Allocation** (heap allocator) | Free it; the memory is the plain payload handed out with it. | — | whoever allocated it |
| **Type key** (sealer) | Unseal objects of the type (§2.3). | Seal objects of the type. | its minter, and whoever it passes the key to |
| **Sealed object** (sealer) | Pass it on; only a key opens it. | — | anyone it is passed to |
| **Credentials** (credential manager) | Use one secret (sign, authenticate to one service) without seeing it. | Derive narrower credentials. | — |

**Quota handles** name a node in a budget tree (§6). `Load` carries the user
right and `Store` the administrative right: deriving smaller quotas of the same
type, and destroying the node. Deriving a disk or network quota returns the
handle asked for plus an administrative one for the creator to keep. Each quota
budgets one resource, and its manager charges it when minting the handles it
enables. The kernel keeps two trees:

| Quota | What it budgets | Handles it enables | User right (`Load`) | Administrative right (`Store`) | Held by |
| --- | --- | --- | --- | --- | --- |
| **VM** | Bytes of memory | Compartments and entry points; also pays for other trees' nodes and for sockets | Allocate memory. | Derive, destroy. | each service that allocates; the shell derives one per program |
| **Thread memory** | Bytes of thread descriptors and stacks | Threads | Create threads. | Derive, destroy. | the shell, and anyone else that creates threads |

User-space managers keep the rest:

| Quota | What it budgets | Handles it enables | User right (`Load`) | Administrative right (`Store`) | Held by |
| --- | --- | --- | --- | --- | --- |
| **CPU** (scheduler) | CPU time per period, with a priority class and guarantee term | None: threads registered on it run | Register threads, query. | Derive, destroy. | the scheduler (root); the shell derives one per worker and program |
| **Disk** (filesystem) | Bytes and inodes under one root directory | Files under that directory | Open, read and list under its root. | Create, write and delete files; derive, destroy. | `fs` (root); the shell: `/home` with both rights, `/bin` with the user right only; one per program |
| **Network** (network service) | Bytes sent and received, and sockets, within a reach (address prefix, ports, protocols) | Sockets within that reach | Open sockets, send and receive within its reach. | Derive, destroy. | `net` (root); the shell; one per program that asks |
| **Heap** (heap allocator) | Bytes of sub-page allocations | Allocations: a sealed handle each, with its plain payload | Allocate small objects. | Derive, destroy. | — |

A leaked quota lets its holder spend or close that budget, and a leaked disk or
network quota exposes exactly its directory subtree or reach; none lets it read
or write anyone's memory.

**Sentries** are sealed code capabilities rather than handles: they name no
object and no manager unseals them, since the hardware does so on the jump or
return that uses one. The kernel makes every call sentry, as it alone holds the
authority to seal one; the hardware makes a return sentry on every call.

| Sentry | Rights | Held by |
| --- | --- | --- |
| **Call sentry** (switcher gate) | Make a call; it carries no authority of its own, since every call also needs an entry point. | every compartment |
| **Return sentry** (hardware) | Return from the call that made it; only a return can use it, and it is local, so only a stack can hold it. | the callee, until it returns |

### 2.2 Global vs. local capabilities

* A thread's stack is **local**, and the return capability (return sentry) written on a call is
  a local one-shot sentry.
* Non-stack memory has store-local permission stripped, so a local capability
  can only be stored into a stack.
* The switcher identifies a real stack by store-local permission, and the
  kernel refuses local capabilities across thread creation.

Passing a local capability therefore lends a buffer for a single call: the
callee cannot keep it outside its stack frame (zeroed on return), avoiding any
revocation sweep (§8).

Each call runs on its own fixed-size slice of the thread's stack, directly
below the caller's slice; its `csp` is bounded to that slice. A stack pointer
passed as an argument loses store-local, and a callee cannot return a pointer
into its own slice.

Stack memory is safe to reuse because a pointer into a slice can only exist
while the call that owns the slice is running:

* the caller's `csp` covers only its own slice, so it cannot make one;
* a stack pointer can only be stored through a capability with store-local:
  the holder's own slice, never a lent buffer, the heap or globals;
* callees return, and have their slices zeroed, before their caller does;
* on return, registers are scrubbed, a pointer into the slice is refused as
  the return value, and the slice is zeroed.

### 2.3 Compartment-minted sealing types

Hardware object types are scarce and fixed at boot. However, any compartment can mint its
own object types dynamically, all sharing the hardware **Type key** and
**Sealed object** types. Both hardware otypes belong to one user-space service, the **sealer**,
which holds their authorities and offers mint, derive, seal and unseal as
ordinary entry points; the kernel is not involved in or aware of virtual sealed types:

1. **Type records and keys.** A type is named by the address of a small record
   in the owner's memory. Minting returns that capability bounded and sealed as
   a **Type key**. Authority over the type comes from owning the memory.
2. **Object layout.**

   ```
   | header (tagged copy of the type key) | payload |
                                           ^ address of the sealed handle and payload
   ```

   Sealing writes a permissionless tagged copy of the key into `header` and
   returns a sealed handle over header and payload. Unsealing checks
   that `header` holds a **tagged** type key with the same
   address and returns a capability bounded to `payload` alone.
4. **Privacy and lifetime.** Typed memory must stay private to the minter, since
   holding a capability over the record lets a compartment mint the same key.
   When the record is freed, the revocation sweep untags every key and header copy.
5. **Creator trust boundary.** A creator can mint types for a child and seed the
   keys into its table. **Sealing protects a compartment from its peers, not
   from its creator.**
6. **Sealer trust boundary.** Whoever holds the type-key authority can mint a
   key for any record address, so the sealer could open any object it is
   handed. Its clients trust it for the integrity of their type system, as they
   trust the scheduler for CPU time; it holds no capability to any client's
   memory beyond the object each call passes, no quota, and no interrupt, so
   it can harm nothing else. Its calls run on the caller's thread with the
   caller's interrupt state, and an object on a swapped-out page is faulted in
   rather than refused.

---

## 3. Compartments, Manifests and Loading

### 3.1 Compartments

A compartment is a protection domain holding memory regions, entry
records, an optional fault handler, and a private **capability table**. 
Its descriptor and table occupy pages billed to its
funding VM quota. It owns no threads.

The descriptor sits at the start of the first page, ahead of the table, and
holds:

* the funding VM quota, which also pays for its entry pages;
* a linked list of virtual memory regions owned by the compartment
* a linked list of entry points
* its fault handler's code sentry, if one is installed (§9);
* a unique ID, a live flag (cleared when it is destroyed), a pageable flag
  (set by its creator: what it allocates may be paged out) and a lock.

| Table slot | Contents |
| --- | --- |
| `0` | The compartment's own handle. Effectively the compartment ID. Sealed as a compartment type. |
| `1` to `6` | What the loader needs (§3.2), filled by the kernel and emptied by the loader as it starts. Reserved for the loader for the compartment's whole life. |
| seeded slots (from `7`) | Initial capabilities in the order supplied by the creator. |
| remaining slots | Free for the compartment's own use. It can store anything it wants in the table. |

The vm quota pays for the compartment's metadata pages.

**Destruction.** Destroying a compartment marks it dead but doesn't immediately destroy it:

* Pages containing its code, capability table, entry records and allocations are **quarantined**,
  not unmapped, so resident threads keep running until a revocation sweep (§8)
  clears every capability into the compartment, including return frames on
  kernel stacks.
* Once swept, any thread trying to return into the dead compartment is unwound to the nearest
  live caller, which gets an error or the thread ends if it was in its entry point compartment
  (no further frames on the call stack).
* Funding quotas used for the memory allocated by the comapartment are refunded when the sweep reclaims 
  the quarantined pages, and any sealing types the compartment minted die with their backing memory.

### 3.2 Images, manifests and loading

Each image declares what it requests in a static
manifest (memory size, syscalls, named services, file/disk handles, MMIO and DMA
memory, interrupts, quotas etc); unmet required entries prevent launch, while unmet
optional entries become null capabilities.

**The manifest is a request.** The launcher (`init`, or anything that starts
programs with `user/launch.hpp`, such as the shell) applies its own policy,
derives each grant from what it holds itself, and builds the compartment
inside the child's quota.

**A compartment loads itself.** The launcher passes the image to
`sys_compartment_create` and gets back a handle that can only destroy the
compartment, plus the entry point of the loader (`boot/loader.cpp`). It calls
the loader once. The loader is kernel-provided code that runs with the new
compartment's own table: it allocates the compartment's memory, copies the
image in, makes its entry point and fault handler, and returns the entry
point. So the launcher never holds a capability to the child's memory. The
kernel loads `init`, the first compartment, itself.

**A program's files.** `launch.hpp` gives each program an ID the first time it
needs one (`/apps/list` maps names to IDs), its own directory `/apps/<id>/own`
and its own disk quota `<id>`, made the first time with the size its manifest
asks for. Anything else it asks for is picked for one run, or given for good
as a link `/apps/<id>/<request>`. Handles are never stored: after a reboot the same
directories, quota and links give it the same handles again.

---

## 4. Entry Points and the Domain Switcher

The switcher enters another domain only through an **entry record** (a descriptor 
reached via a sealed entry-point handle) rather than a
bare sealed (otype 1 sentry) code pointer because it needs:

* the call sentry, the cgp
* per-entry metadata, including minimum stack space and whether the entry is a
  kernel syscall carrying system-register access.

The entry record pointed to by the sentry contains everything necessary to invoke a compartment

The switcher gate is the **only** jumpable call sentry the kernel gives a
compartment; every cross-domain call and syscall passes through it.

Attempting to invoke a SignetOS sentry will produce a seal fault 
to prevent the switcher being bypassed.

### Cross-compartment call sequence

1. **Validate & push:** verify the entry handle, check the target compartment isn't marked as dead; 
  push caller state onto the thread's kernel return stack (trusted stack only accessible by the kernel), failing if full.
2. **Stack slice:** give the callee its own `min_stack` slice directly below the
   caller's, failing if the thread's stack has no room left.
3. **Scrub & enter:** zero the callee's stack region and all non-argument
   registers, switch to the callee's capability table (cgp), and jump (keeping
   interrupt state for user calls, masking interrupts for syscalls).
4. **Return & scrub:** verify the return frame (a forged or replayed return
   kills the thread), **zero the entire stack slice lent to the callee** and all
   volatile non-return registers, restore the caller's table, and resume.

---

## 5. Threads and Termination

A thread is a CPU state it has a user stack, and a small trusted stack (**kernel
return stack**) for switcher and trap frames only (syscall bodies run on a slice
of the caller's user stack). The thread including stack is funded from a thread-memory quota and scheduled
under a CPU quota (scheduler managed, the kernel has no in), threads migrate across compartments on calls and read their
own ID from a kernel-updated read-only register.

Its descriptor sits at the front of two pages, with the kernel return stack
behind it, and holds:

* the thread-memory quota that paid for those pages and the user stack;
* its user stack, and the slice of it its entry was given;
* its initial entry point;
* pointer to trusted kernel stack which holds return frames;
* its unique ID and its flags (live, running, started, kill pending).

It records no compartment and no scheduling state: the compartment it is in
follows from its entry point and the switcher frames on its kernel return
stack, and the scheduler keeps its own records.

### Stopping, killing and unwinding a thread

Stopping a thread from consuming CPU, reclaiming its memory, and forcing it out
of a compartment are separate mechanisms:

* **Revoking CPU quota (stopping):** destroying or revoking the thread's CPU
  quota node in the scheduler stops it from being picked from the next timer
  tick (user code cannot mask the tick), without actually killing (destroying) the thread or freeing
  its memory. If the stopped thread holds a contended lock inside a service,
  waiting callers lend it CPU budget to finish the critical section (§7). The thread
  can then be rescheduled again in the future.
* **Killing the thread (`sys_thread_kill`):** reclaims the thread's stack and
  descriptor pages. **A kill never cuts an active call short**—the kernel ends
  the thread only when it returns to its own root compartment:
  * Active calls, syscalls and trap handlers run to normal return.
  * Blocked service waits fail immediately so the service releases locks on its
    normal error path and returns up to the thread's root code, where the thread
    ends (a stopped thread is placed on the killer's CPU node first so the
    killer funds its teardown).
  * A thread wedged in an unresponsive callee therefore costs its creator no CPU
    time (once its CPU quota is revoked) and only some pages of thread-memory
    quota until the callee returns or is destroyed.
* **Destroying the compartment:** if a thread is inside a compartment that is
  destroyed (for example, to break out of a callee that spins without
  returning), the kernel unwinds the thread past the dead frames to the nearest
  live caller once the revocation sweep completes (§3.1), or ends the thread if
  that was its root compartment.
* **Synchronous fault:** handled by the faulting compartment's own fault handler
  or unwound (§9), returning an error to the caller (or ending the thread at its
  root).

Because a live callee is never aborted mid-task from outside, compartments
need no asynchronous cleanup handlers; they must only protect shared state with
a scheduler lock, return when a wait fails, keep non-waiting work bounded, and
handle dead-owner lock handoff.

Locks are currently mediated by the scheduler.

---

## 6. Quotas

Each resource manager owns a quota tree in its own dimension (VM and thread
memory in the kernel, CPU bandwidth in the scheduler, storage in the
filesystem, network traffic in the network service):

1. **Caller-funded nodes.** Every quota node is a thing that lives in memory and thus is paid for by a caller VM
   quota, never the manager (to prevent exhaustion as an attack vector). VM quota derivations debit the child's allowance
   *plus the node page itself* from the parent node, bounding runaway derivation.
   The CPU, disk and network managers take a caller VM quota to allocate the node page;
   closing that VM quota early waits until the manager frees the page.
2. **Immutable static partitions.** Budgets are fixed at derivation with no
   runtime resize; over-budget requests fail at once.
3. **No reparenting (close, cascade or refuse).** Destroying a node never moves
   its children to another parent:
   * **Kernel memory trees close:** the subtree refuses new charges and refunds
     all unused allowance to the parent at once, while closed nodes stay until
     sweeps refund their remaining allocations up to the first live ancestor.
     This means that anything funded by a closed memory quota subtree can still 
     exist until freed (preventing memory objects from just disappearing) but 
     nothing new can be allocated with the subtree quota nodes since the unused
     quota is returned to the parent of the killed node. Once a killed quota node 
     no longer has any allocations which were funded by it, it will itself be destroyed
     and the refund returns up the tree.
   * **Scheduler CPU trees cascade:** the node and its subtree are freed at
     once, returning bandwidth to the parent and stopping its threads (§7).


* **CPU quotas:** specify `budget / period`, priority class (at most the
  parent's), and guarantee term: 
  A guarantee term allows a subquota to be derived as revocable anytime, 
  revocable after an amount of time or never revocable.
  **Revocable** (at any time), **Fixed term**
  (until expiry), or **Permanent** (never). Destroying a child node requires
  the *parent* handle, so a holder cannot revoke its own node.
* **Disk quotas:** bound bytes only, and give access to nothing: access is a
  separate handle on a file or directory, whose read, add, change and link
  rights only shrink, down to everything under a directory (`boot/fs.cpp`).
  Each file is paid for by the quota its creator named, and growing it needs
  that quota too. Every entry costs a block. Each quota keeps what it pays for
  in `used` on disk: a charge is written before the change it pays for and a
  refund after, so a crash can only leave it too high, and nothing is counted
  at run time.
  A handle with change on a quota can split it, resize the parts (growing takes
  from it, shrinking stops at `used`) or remove one that pays for nothing. A handle is a record paid for by the memory quota of
  whoever opened it; closing it closes every handle opened through it. A link
  names a file or directory with rights; only a handle with link can be linked
  to.
* **Network quotas:** bound bytes sent, bytes received and open sockets, within
  a reach (an IPv4 prefix, port ranges and protocols) that a child can only
  narrow.

## 7. Scheduling and Synchronisation

Scheduling policy and run queues live in the user-space scheduler. The kernel
provides thread switching, a timer tick routed to the scheduler, and re-entry
into the scheduler whenever a thread exits.

* **Budgets and overruns:** each CPU quota node has its budget refilled every
  period, and the scheduler deducts time from it on every thread switch and
  timer tick. Because threads are only preempted on timer ticks, a thread can
  run up to one tick past its budget; that extra time is subtracted from its
  next period's budget so a node with a small budget still gets its fair share
  over time. When nothing else is runnable, spare CPU time is not charged to
  anyone.
* **Destroying a CPU quota:** when a CPU quota subtree is destroyed, its threads
  simply stop running where they are rather than being moved onto the parent's
  quota (where they would eat into the parent's own CPU time).
* **Locks and lending CPU time to lock holders:** an uncontended lock is an
  atomic word in the compartment's own memory holding the owner's thread ID,
  taken and released with a single compare-and-swap. If the lock is already
  held, the waiting thread calls the scheduler and passes a **read-only
  capability** to the lock word so the scheduler can check who holds it without
  being able to write to the compartment's memory. While waiting, if the
  scheduler picks the waiting thread to run, **it runs the lock holder instead,
  using the waiting thread's CPU budget and priority** (and following the chain
  if that holder is waiting on another lock). This ensures a thread that ran out
  of budget—or had its CPU quota revoked—while holding a lock in a shared
  service is still given CPU time to finish and release the lock. When the lock
  is released, the scheduler tells the compartment which waiting thread is next,
  and the compartment updates its own lock word.

---

## 8. Memory Management, Paging and Revocation

| Sharing model | Mechanism |
| --- | --- |
| **1. Ephemeral borrowing** | Local capabilities in call arguments; hardware prevents non-stack storage, so access ends on return with no sweep. |
| **2. Persistent handles** | Sealed capabilities (hardware or compartment types) opaque to holders and opened only by the manager. |
| **3. Shared global memory** | Global capabilities across compartments; memory passes through quarantine and revocation before reuse. |

* **The base rule:** a revocation sweep clears the tag of every live capability
  whose *base* lies in a quarantined allocation (memory unmap) or a marked sub-range
  (capabilities based outside a marked sub-range, like a heap's arena
  capability, survive).
* **Revocable arenas:** an allocation (vm_allocate) made with `FLAG_REVOCABLE`, which its
  owner (a heap, typically) hands out in pieces. It is the only memory that can
  be revoked in part: the owner marks a freed sub-range with `sys_revoke`, and
  the next sweep untags every capability based inside it. The arena's first
  byte can never be marked, so the owner's own capability to the whole arena
  survives. Ordinary allocations are only ever revoked whole, when freed.
* **Pre-funded marks:** a revocable arena pays up front, from the same quota,
  for its revocation bitmaps (one bit per 16 bytes, and two bitmaps, so two
  pages per 512 KiB: a mark made while a sweep runs goes in the one that
  sweep does not clear), so marking freed sub-ranges costs no memory, is
  never refused, and sweep checks are `O(1)`.
* **Charged until swept:** quarantined memory stays charged as *owed* on its
  funding quota until a sweep reclaims it and refunds owed bytes, so rapid
  alloc/free loops exhaust only the freer's own quota.
* **Sweeps in the background:** a compartment starts a sweep when it wants
  memory back (`sys_revoke_start`); nothing stops the machine to scan. From
  the start of a sweep a page is checked before the first capability is
  loaded from it, at the expense of whoever loads it, and the pages nobody
  touches are checked by the `sweeper` thread, whose CPU quota bounds the
  time spent sweeping in the background. Memory freed while a sweep runs is
  reclaimed by the next one.
* **Capability-safe paging:** on eviction to disk, the kernel
  records a per-slot capability tag bitmap and page digest (hash). 
  On page-in, it verifies the digest and rebuilds capabilities from its
  root, dropping any revoked capability (and holding swept virtual addresses out
  of reuse until swapped capability pages are checked). During revocation the 
  page on the disk is checked for revoked capabilities and if present the corresponding 
  bit in the bitmap is cleared so that the capability is not reconstructed when paged in.
  A compartment's memory is pageable only if its creator asks
  (`COMPARTMENT_PAGEABLE`): `init` asks for none of what it starts, the shell
  for the programs it runs. Paging is a build option (`make PAGING=0`):
  without it the kernel has no paging code or system calls, there is no pager
  and no swap, and all memory stays in RAM.
* **Bounded DMA:** drivers never see physical addresses or writable descriptor
  rings; an isolated `dma` compartment confines DMA to a fixed window and
  configures static descriptor chains at boot.

---

## 9. Interrupts and Per-Compartment Faults

Interrupts and synchronous faults take separate paths: every interrupt goes to
one handler on its own thread, whereas synchronous faults go strictly to **the
compartment that faulted**, never to a global handler (unless handled by the kernel like a page fault).

* **Interrupts:** boot installs one handler thread per hart, an ordinary
  thread on the scheduler's interrupt entry that the hart holds. On a tick
  or device interrupt the kernel parks the interrupted thread and resumes
  the handler from its wait (`sys_trap_wait`), masked; it waits again naming
  which thread to run next. The scheduler owns the PLIC: a
  device interrupt just wakes the driver thread waiting for it
  (`sched.irq_wait`). Nothing runs on the interrupted thread.
* **Fault identification:** each compartment may register a private code sentry
  as its fault handler in its kernel descriptor. On trap, the kernel identifies
  the faulting compartment from its own trusted frame beneath the trap—never
  from untrusted compartment registers.
* **Fault delivery and resolution:** the kernel places a saved register snapshot
  and raw fault cause on the faulting stack (with the PC as a plain address,
  never an executable capability) and calls the handler:
  * **Resume:** reloads the edited registers within the original code
    capability's bounds (allowing instruction skip, retry, register repair, or
    recovery jumps).
  * **Unwind:** chosen by the handler, or forced when no handler exists, stack
    space is full, or the handler itself faults. The frame is scrubbed and
    popped, returning an error to the caller (or ending the thread at its root).
    Only a fault in the kernel halts the machine.

---

## 10. Privilege by Sealed Type

Everything a compartment can do beyond accessing its own memory comes from a
sealed capability in its table. So the privilege of the system can be read off
three questions per type: who can seal it (holds the sealing authority), who
holds instances, and what an instance lets its holder do. The tables in §2.1
answer all three.

After `init` exits, the only places a handle can be sealed are the kernel (its
own types), the scheduler (CPU quotas), the filesystem (disk quotas and files),
the network service (network quotas and sockets) and the sealer (type keys and
sealed objects). Future managers, such as a heap allocator or a credential
manager, add to these.

### 10.1 Kernel gates by holder

Which syscall gates a compartment holds decides what it can ask the kernel to
do. As granted by `init` today:

| Gate(s) | Held by | What it allows |
| --- | --- | --- |
| `compartment_invoke` | everyone | The switcher gate itself. |
| `sentry` | `uart`, `blk`, `fs`, `naming`, `sealer`, `sched`; no program | Create entry points to export. |
| `vm_allocate`, `vm_deallocate` | `fs`, `sched`, `shell` etc.| Allocate against a VM quota it holds. `uart`, `dma`, `blk`, `naming` and programs cannot allocate at all after load. |
| `thread_switch`, `thread_tid` | `sched` | The only compartment that can run a thread. |
| `thread_kill` | `sched` | End a thread it holds a handle to. |
| `trap_wait` | `sched` | The interrupt handler's wait. Refused to anyone but the hart's installed handler while it handles an interrupt. |
| `compartment_create`, `compartment_destroy`, `thread_create`, `quota_vm_derive`, `quota_vm_destroy` | `shell` only | Build and tear down compartments and threads, funded from its own quotas: the launcher role. A compartment it makes from an image loads itself (§3.2), so the shell holds only a handle that can destroy it. |
| `vm_allocate`, `sentry`, `fault_install` (in slots 1 to 6) | each compartment made from an image, while its loader runs | Load the image (§3.2). The loader takes them out of the table as it starts, so the image never sees them. |
| `page_next`, `page_done` | `blk` only | The pager: move pages between RAM and swap (contents and capability bitmaps are checked by the kernel, §8). Only in a build with paging. Still evolving WIP.|
| `revoke_start`, `revoke_query` | `shell` | Start a sweep, and see when it is complete. |
| `revoke_step` | `sweeper` only | Check the pages a running sweep has not reached, a few at a time. |
| `trap_install`, `page_setup`, `quota_*_create_root` | `init` only, scrubbed when it exits | Boot setup: installing the interrupt handler thread, enabling paging, and creating root physical quotas are fundamentally unreachable after boot. |
| `quota_thread_mem_derive`, `quota_thread_mem_destroy`, `cow`, `revoke` | `init` only (current WIP) | Implementation artifacts: `shell` currently allocates threads from a flat quota rather than deriving sub-trees, and lazy CoW / user-triggered revocation are not yet wired up. |

Beyond gates, three compartments hold raw hardware: `uart` its device window,
`sched` the interrupt controller, and `dma` the virtio window and the DMA
arena. `dma` runs once, writes the only device-visible physical addresses, and
hands `blk` views that reach neither the descriptor table nor the queue
registers.
