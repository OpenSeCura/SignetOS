# SignetOS Core Design

SignetOS is a single-address-space, single-privilege-level capability microkernel
for CHERI architectures. Isolation is enforced by capabilities alone; the MMU is
used for address translation, never for protection.

---

## 1. Architecture

| Principle | Design |
| --- | --- |
| **Single virtual address space** | One address space and one page table shared by everything; nothing is remapped on switches or calls. |
| **Single privilege level** | One CPU privilege level with permissive page-table entries; only kernel entry points hold system-register access. |
| **Migrating threads** | Threads do not belong to compartments; they cross domains through the switcher, with a small kernel stack recording active calls and traps. |
| **Capability syscalls** | Kernel syscalls are entry points invoked through the *same* switcher gate as any cross-compartment call. |
| **Quarantine & up-front quotas** | Freed pages stay mapped in quarantine until a sweep clears all tags to them, and quotas are debited up front on allocation. |

**Kernel vs. user space.** The kernel provides only mechanisms requiring
system-register or sealing-root access: the domain switcher, virtual memory,
memory and thread-memory quotas, sealing of its own handles, contiguous DMA
allocation (`FLAG_DMA`), revocation sweeps, and trap delivery. Scheduling,
filesystems, drivers, interrupt routing, naming, compartment-minted sealing
types, and program loading all run as unprivileged compartments holding only
what is in their capability tables.

**Bootstrap.** At boot, the kernel creates one compartment (`init`) seeded with
the root quotas, all syscall gates, device windows, and service sealing
authorities. `init` starts the core services (console, block driver, filesystem,
naming, sealing service, scheduler, interrupt manager, shell), grants each only
what its manifest requests, hands the scheduler's dispatch entry to the kernel,
clears its own table, and exits.

---

## 2. Capabilities and Sealing

### 2.1 Hardware capability types

Each hardware object type belongs to a resource manager, which holds the
authority to seal and unseal it. The kernel delegates the CPU-quota, disk-quota,
type-key and sealed-object types (sealing/unsealing capabilities) to the
user-space scheduler, filesystem and sealing service at boot and holds the rest
itself.

Sealed types managed by the kernel:

| Type | Purpose |
| --- | --- |
| **Sentry** | Jumpable code token. The kernel hands out only the switcher gate; compartments can seal sentries over their own code. |
| **Entry point** | Handle to a kernel-written entry record for a compartment or syscall (§4). |
| **Compartment** | Handle to a compartment (§3). |
| **Thread** | Handle to a thread (§5). |
| **VM quota** | Hierarchical virtual-memory budget (§6). |
| **Thread-memory quota** | Hierarchical budget for thread descriptors and stacks (§6). |

Sealed types managed by user-space services:

| Type | Manager | Purpose |
| --- | --- | --- |
| **CPU quota** | scheduler | Hierarchical CPU-bandwidth budget (§6, §7). |
| **Disk quota** | filesystem | Hierarchical storage budget and open-file handles (§6). |
| **Type key** | sealer | Compartment-minted type key (§2.3). |
| **Sealed object** | sealer | Compartment-sealed object (§2.3). |

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

### 2.3 Compartment-minted sealing types

Hardware object types are scarce and fixed at boot. Any compartment can mint its
own object types dynamically, all sharing the hardware **Type key** and
**Sealed object** types. Both belong to one user-space service, the **sealer**,
which holds their authorities and offers mint, derive, seal and unseal as
ordinary entry points; the kernel neither mints keys nor opens objects, and the
mechanism needs no kernel memory:

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

| Table slot | Contents |
| --- | --- |
| `0` | The compartment's own handle. Effectively the compartment ID. Sealed as a compartment type. |
| seeded slots | Initial capabilities in the order supplied by the creator. |
| remaining slots | Free for the compartment's own use. It can store anything it wants in the table. |

The vm quota pays for the compartment's metadata pages.

**Destruction.** Destroying a compartment marks it dead but doesn't immediately destroy it:

* Its code, capability table, entry records and allocations are **quarantined**,
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

**The manifest is a request, never an authority.** The launcher (`init` or the
shell or some other launcher) applies its own policy, derives each grant from what it holds itself,
builds the compartment inside the child's quota, and installs its entry point
and fault handler.

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
2. **Narrow stack:** verify it is a real stack by store-local permission and narrow it
   to the unused region *below* the caller's stack pointer (or a fixed slice for
   syscalls), failing if below the minimum needed.
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
filesystem, network and more to come soon):

1. **Caller-funded nodes.** Every quota node is a thing that lives in memory and thus is paid for by a caller VM
   quota, never the manager (to prevent exhaustion as an attack vector). VM quota derivations debit the child's allowance
   *plus the node page itself* from the parent node, bounding runaway derivation.
   CPU and disk managers etc take a caller VM quota to allocate the node page;
   closing that VM quota early waits until the manager frees the page.
2. **Immutable static partitions.** Budgets are fixed at derivation with no
   runtime resize; over-budget requests fail at once.
3. **No reparenting (close vs. cascade).** Destroying a node never moves its
   children to another parent:
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

### Domain-specific nodes

* **CPU quotas:** specify `budget / period`, priority class (at most the
  parent's), and guarantee term: 
  A guarantee term allows a subquota to be derived as revocable anytime, 
  revocable after an amount of time or never revocable.
  **Revocable** (at any time), **Fixed term**
  (until expiry), or **Permanent** (never). Destroying a child node requires
  the *parent* handle, so a holder cannot revoke its own node.
* **Disk quotas:** bound bytes and files within a directory path.

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
* **Pre-funded marks:** revocable arenas pay up front at allocation for their
  virtual-address revocation bitmap pages, so marking freed sub-ranges costs no
  memory and sweep checks are `O(1)`.
* **Charged until swept:** quarantined memory stays charged as *owed* on its
  funding quota until a sweep reclaims it and refunds owed bytes, so rapid
  alloc/free loops exhaust only the freer's own quota.
* **Rate-limited sweeps:** sweeps run at most once per minimum interval rather
  than on demand, bounding total CPU time spent sweeping.
* **Capability-safe paging:** on eviction to disk, the kernel
  records a per-slot capability tag bitmap and page digest (hash). 
  On page-in, it verifies the digest and rebuilds capabilities from its
  root, dropping any revoked capability (and holding swept virtual addresses out
  of reuse until swapped capability pages are checked). During revocation the 
  page on the disk is checked for revoked capabilities and if present the corresponding 
  bit in the bitmap is cleared so that the capability is not reconstructed when paged in.
* **Bounded DMA:** drivers never see physical addresses or writable descriptor
  rings; an isolated `dma` compartment confines DMA to a fixed window and
  configures static descriptor chains at boot.

---

## 9. Interrupts and Per-Compartment Faults

Interrupts and synchronous faults take separate paths: only two interrupts leave
the kernel, whereas synchronous faults go strictly to **the compartment that
faulted**, never to a global handler (unless handled by the kernel like a page fault).

* **Interrupts:** boot installs fixed handlers for timer ticks (scheduler) and
  external device interrupts (interrupt manager, which claims sources and calls
  driver handlers). Both run with interrupts masked on the **interrupted
  thread's narrowed stack**, scrubbed on return. (Currently investigating if interrupt handling
  should be moved to a dedicated waiting thread)
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
holds instances, and what an instance lets its holder do.

### 10.1 The types

| Type | Sealed by | Who holds instances | What an instance lets the holder do |
| --- | --- | --- | --- |
| **Sentry** (switcher gate) | kernel | every compartment | Make a call. Carries no authority of its own: every call also needs an entry-point handle. |
| **Entry point** (kernel syscall gate) | kernel; all seeded into `init`, which hands each out per manifest | see §10.2 | Invoke that syscall. Only a gate available to a compartment can be called. |
| **Entry point** (service entry) | the exporting service, over its own code; handed out through `naming` or returned to `init` in some cases (implementation detail right now) | the clients that named it in their manifest AND the policy of the compartment that lauched it allowed it | Invoke that entry point via the switcher. |
| **Compartment** | kernel | the compartment itself and its launcher | Name the compartment to the syscalls that act on it: allocate memory it owns, create its entry points, install its fault handler, revoke its sub-ranges, destroy it. |
| **Thread** | kernel | its creator; the scheduler (passed in at registration) | Switch to it (with `thread_switch`), kill it (with `thread_kill`). |
| **VM quota** | kernel; root seeded into `init` | one per service that allocates (`fs`, `sched`, `trap_mgr`, `shell` etc); the shell derives a sub-quota per program | Allocate memory against it, derive and destroy children. A leak lets the holder spend or close that budget, never read or write anyone's memory. |
| **Thread-memory quota** | kernel; root seeded into `init` | `shell` etc, anyone who would need to create threads. | Fund thread descriptors and stacks (with `thread_create`). |
| **CPU quota** | **scheduler** (authority handed to it by `init`) | root in the scheduler; the shell holds its own node and derives a child per worker and program | Register threads under it, derive children, query. |
| **Disk quota / file handle** | **filesystem** (authority handed to it by `init`) | `fs` holds the root; `shell` holds `/home` (read-write) and `/bin` (read-only); each program gets a node under `/home` plus any files the shell opens for it | Filesystem operations confined to the node's directory subtree, with the handle's rights. A leak exposes exactly that subtree. |
| **Type key / Sealed object** | **sealer** (authorities handed to it by `init`) | nobody in the default image | Seal and unseal objects of one compartment-defined type. A leaked key is forgery within that type only. |

After `init` exits, the only places a handle can be sealed are the kernel (its
own types), the scheduler (CPU quota), the filesystem (disk quota) and the
sealer (type keys and sealed objects). Future types such as network or credential quotas will add to these types.

### 10.2 Kernel gates by holder

Which syscall gates a compartment holds decides what it can ask the kernel to
do. As granted by `init` today:

| Gate(s) | Held by | What it allows |
| --- | --- | --- |
| `compartment_invoke` | everyone | The switcher gate itself. |
| `sentry` | every service; no program | Create entry points to export. |
| `vm_allocate`, `vm_deallocate` | `fs`, `sched`, `trap_mgr`, `shell` etc.| Allocate against a VM quota it holds. `uart`, `dma`, `blk`, `naming` and programs cannot allocate at all after load. |
| `thread_switch`, `thread_tid` | `sched` | The only compartment that can run a thread. |
| `thread_kill` | `sched` | End a thread it holds a handle to. |
| `compartment_create`, `compartment_destroy`, `thread_create`, `fault_install`, `quota_vm_derive`, `quota_vm_destroy` | `shell` only | Build and tear down compartments and threads, funded from its own quotas: the launcher role. |
| `page_next`, `page_done` | `blk` only | The pager: move pages between RAM and swap (contents and capability bitmaps are checked by the kernel, §8). Still evolving WIP.|
| `revoke_query` | `shell` | Ask for a rate-limited sweep. |
| `trap_install`, `page_setup`, `quota_*_create_root` | `init` only, scrubbed when it exits | Boot setup: binding hardware IRQs, enabling paging, and creating root physical quotas are fundamentally unreachable after boot. |
| `quota_thread_mem_derive`, `quota_thread_mem_destroy`, `cow`, `revoke` | `init` only (current WIP) | Implementation artifacts: `shell` currently allocates threads from a flat quota rather than deriving sub-trees, and lazy CoW / user-triggered revocation are not yet wired up. |

Beyond gates, three compartments hold raw hardware: `uart` its device window,
`trap_mgr` the interrupt controller, and `dma` the virtio window and the DMA
arena. `dma` runs once, writes the only device-visible physical addresses, and
hands `blk` views that reach neither the descriptor table nor the queue
registers.
