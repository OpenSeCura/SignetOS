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
 * heap.cpp - SignetOS User-Space Heap Service Compartment
 *
 * Hands out heap memory to other compartments: the `heap.*` entries of
 * abi.hpp, "Heap service". `init` invokes it once: it hands the revocation
 * and lock gates to user/heap.hpp, publishes the entries and returns. After
 * that it runs only through the entries, on the caller's thread.
 *
 * HEAPS
 *   Each heap is a revocable arena owned by this compartment (so it can
 *   revoke parts of it) and paid for by the client's VM quota. The service
 *   keeps one `Slot` per heap: the arena, that quota, and the lock. The
 *   allocator state and the quota nodes live in the arena. At most
 *   init::HEAP_MAX_HEAPS heaps.
 *
 * HANDLES
 *   Only this service can seal or unseal heap handles. A quota handle
 *   (OType::QuotaHeap) is the quota's node, bounded, with Permit_Load
 *   (alloc), Permit_Store (derive, destroy) or both. An allocation handle
 *   (OType::HeapAllocation) is the block with no permissions. Either has the
 *   base of a heap block, so the sweep after that block is freed untags it.
 *   Until then it still unseals, so what it names is checked again under
 *   the heap's lock (`live_node`, `Heap::Session::free`).
 *
 * WHICH HEAP
 *   A handle's heap is the live one whose arena holds its address (`find`).
 *   The kernel never hands out an address twice, so a handle to a destroyed
 *   heap finds none, even if its Slot holds a new heap.
 *
 * THE TREE OF QUOTAS: A STATIC PARTITION
 *   See abi.hpp, QUOTAS FORM A TREE. A quota (heap.hpp, WHO PAYS) lives in
 *   its node, and a chunk's header names its quota's node. A parent pays up
 *   front for a child's whole limit and its node, so no request looks above
 *   the quota it names. A chunk stays charged until it leaves quarantine
 *   (`heap::released`). Refunds to a closed quota pass up to the first live
 *   one (`refund`); its node is freed once nothing is charged to it
 *   (`reap`). No quota ever moves to another parent.
 *
 * LOCKING, AND FAULTS
 *   Each heap has its own lock, held only around work on that heap. With it
 *   held the service touches no memory a client handed it: arguments are
 *   checked before, results stored after. A fault with the lock held would
 *   stall the heap until the thread ends, then break it for good (heap.hpp,
 *   LOCKING); a bad pointer must not be able to do that. The Slot table has
 *   no lock (see `Slot`).
 *
 * WHAT IT HOLDS
 *   See HEAP_MANIFEST. Besides the two sealing authorities: `vm_*` for the
 *   arenas, `revoke*` for quarantine, `sched.lock_*` to wait for a heap's
 *   lock, `sched.block` for `heap.wait`, and `sentry` and `naming.publish`
 *   for its entries. No VM quota: every arena is paid for by a client's.
 *
 * HEAP_DEBUG=1 (Makefile) builds in the allocator's own checks (heap.hpp,
 * BUILDING).
 */

#include "runtime.hpp"

// Before heap.hpp: accounts and sessions (heap.hpp, WHO PAYS).
#define SIGNETOS_HEAP_OWNERS 1
#include "heap.hpp"

namespace signetos::user {
namespace {

// --- What `heap` asks `init` for (user/manifest.hpp) -------------------------
#define HEAP_MANIFEST(X)                                     \
  M_OTYPE(X, SEAL_QUOTA, ::signetos::OType::QuotaHeap)       \
  M_OTYPE(X, SEAL_ALLOC, ::signetos::OType::HeapAllocation)  \
  M_SYSCALL(X, SYS_VM_ALLOC, vm_allocate)                    \
  M_SYSCALL(X, SYS_VM_DEALLOC, vm_deallocate)                \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)          \
  M_SYSCALL(X, SYS_REVOKE, revoke)                           \
  M_SYSCALL(X, SYS_REVOKE_QUERY, revoke_query)               \
  M_SYSCALL(X, SYS_REVOKE_START, revoke_start)               \
  M_SYSCALL(X, SYS_SENTRY, sentry)                           \
  M_SERVICE(X, UART_SENTRY, "uart")                          \
  M_SERVICE(X, SCHED_LOCK_WAIT, "sched.lock_wait")           \
  M_SERVICE(X, SCHED_LOCK_WAKE, "sched.lock_wake")           \
  M_SERVICE(X, NAMING_PUBLISH, "naming.publish")             \
  M_SERVICE(X, SCHED_BLOCK, "sched.block")

// Room for the image.
constexpr size_t IMAGE_BYTES = 120 * 1024;

SIGNETOS_MANIFEST(HEAP_MANIFEST, IMAGE_BYTES)

// Runtime slots: the entry points minted at startup, kept so that the table
// records everything this compartment has made.
constexpr size_t SLOT_ENTRY_BASE =
    compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT;

bool s_online = false;

// --- Clients' heaps ----------------------------------------------------------

// What the entries need of the capability table, copied out once checked.
Capability s_invoke = nullptr;      // the switcher
Capability s_self = nullptr;        // this compartment: it owns every arena
Capability s_vm_alloc = nullptr;    // `sys_vm_allocate`
Capability s_vm_dealloc = nullptr;  // `sys_vm_deallocate`
Capability s_sched_block = nullptr; // `sched.block`, for `heap.wait`
Capability s_auth_quota = nullptr;  // over OType::QuotaHeap
Capability s_auth_alloc = nullptr;  // over OType::HeapAllocation

// A quota's node: a block of the heap it accounts for, out of clients' reach.
struct alignas(16) Node {
  heap::Account account;  // the limit, and what is charged now
  uint64_t state;         // NODE_LIVE or NODE_CLOSED; else not a quota
  // Tree links, as chunk owner ids (`owner_of`); 0 is none.
  uint32_t parent;        // 0 in a root quota
  uint32_t child;         // its first child
  uint32_t next;          // the next child of the same parent
  uint32_t prev;          // and the one before; 0 in the first
  uint32_t root;          // the heap's root quota; itself, in the root
  uint32_t reap;          // next closed node to free; in the root, the first
};
static_assert(sizeof(Node) == init::HEAP_NODE_BYTES);
// Values that zeroed memory and small numbers never have.
constexpr uint64_t NODE_LIVE = 0x4c49564551554f54ULL;    // "TOUQEVIL"
constexpr uint64_t NODE_CLOSED = 0x4445534f4c43514fULL;  // "OQCLOSED"

constexpr uint64_t QUOTA_RIGHTS = perms::Load | perms::Store;

// A chunk's owner (29 header bits) is its quota's node offset in the arena,
// in 16-byte units (the allocator's alignment). The top bit marks a chunk
// that holds a child quota's node, charged to the parent.
constexpr uint64_t OWNER_SHIFT = 4;
constexpr uint32_t NODE_CHUNK = 1u << 28;
static_assert((init::HEAP_MAX_BYTES >> OWNER_SHIFT) <= NODE_CHUNK);

// One heap. It changes hands by compare-and-swap on `state`: the phase in
// the low bits, and above them a count of the heaps it held before, so a
// thread that waited for a heap's lock can tell if it is still that heap.
// The other fields are written only by the thread that made the Slot
// SLOT_BUSY, and are valid only while SLOT_LIVE.
struct Slot {
  uint64_t state;
  uint64_t base;        // the arena is [base, top)
  uint64_t top;
  uint64_t root;        // the address of the root quota's node
  Capability arena;     // the whole allocation
  Capability vm_quota;  // what paid for it, to give it back against
  heap::Heap heap;
};
constexpr uint64_t SLOT_PHASE = 3;
constexpr uint64_t SLOT_FREE = 0;  // no heap
constexpr uint64_t SLOT_BUSY = 1;  // being made, or being given up
constexpr uint64_t SLOT_LIVE = 2;  // a heap
constexpr uint64_t SLOT_NEXT = 4;  // added when a Slot is given up

constinit Slot s_slots[init::HEAP_MAX_HEAPS] = {};

inline uint64_t load(const uint64_t* word) {
  return __atomic_load_n(word, __ATOMIC_SEQ_CST);
}
inline void store(uint64_t* word, uint64_t value) {
  __atomic_store_n(word, value, __ATOMIC_SEQ_CST);
}
inline bool swap(uint64_t* word, uint64_t from, uint64_t to) {
  return __atomic_compare_exchange_n(word, &from, to, false, __ATOMIC_SEQ_CST,
                                     __ATOMIC_SEQ_CST);
}

// The live heap whose arena holds `address`, or null; `*seen` is its state.
// Takes no lock: a caller that then enters the heap must check `same`.
Slot* find(uint64_t address, uint64_t* seen) {
  for (Slot& slot : s_slots) {
    const uint64_t state = load(&slot.state);
    if ((state & SLOT_PHASE) != SLOT_LIVE) {
      continue;
    }
    const uint64_t base = load(&slot.base);
    const uint64_t top = load(&slot.top);
    // The bounds are this heap's only if the state did not change meanwhile.
    if (address >= base && address < top && load(&slot.state) == state) {
      *seen = state;
      return &slot;
    }
  }
  return nullptr;
}

// With the heap's lock held: whether the Slot still holds the heap `find`
// saw. If so it keeps it until the lock is let go, since a heap that can be
// entered is given up only from inside (`heap_destroy_entry`).
inline bool same(const Slot& slot, uint64_t seen) {
  return load(&slot.state) == seen;
}

// The node at `address`, through the service's capability to the whole
// arena, which no sweep of part of the arena revokes.
inline Node* node_at(const Slot& slot, uint64_t address) {
  return reinterpret_cast<Node*>(capability_set_address(slot.arena, address));
}

// A node address as a chunk owner id (`node_of` is the inverse).
inline uint32_t owner_of(const Slot& slot, uint64_t address) {
  return static_cast<uint32_t>((address - slot.base) >> OWNER_SHIFT);
}

// A sealed handle to the node at `address`: bounded, with only `rights`.
Capability seal_quota(const Slot& slot, uint64_t address, uint64_t rights) {
  Capability node = capability_set_address(slot.arena, address);
  node = capability_set_bounds(node, sizeof(Node));
  node = capability_and_perms(node, rights & QUOTA_RIGHTS);
  return sealing::seal_with(s_auth_quota, node);
}

// --- The tree of quotas ------------------------------------------------------
//
// `refund`, `to_reap` and `close_subtree` run with the heap's lock held and
// touch only nodes, never the allocator: `refund` runs inside it
// (`heap::released`).

// Owner id to node, and node to owner id. `arena` must have the arena's
// base; its address does not matter.
inline Node* node_of(Capability arena, uint32_t owner) {
  return reinterpret_cast<Node*>(capability_set_address(
      arena, capability_get_base(arena) +
                 (uint64_t{owner & ~NODE_CHUNK} << OWNER_SHIFT)));
}
inline uint32_t id_of(Capability arena, Node* node) {
  return static_cast<uint32_t>(
      (capability_get_address(reinterpret_cast<Capability>(node)) -
       capability_get_base(arena)) >>
      OWNER_SHIFT);
}

// Queues a closed quota with nothing charged to it for `reap`. Once only:
// a closed quota is never charged again.
inline void to_reap(Capability arena, Node* node) {
  Node* root = node_of(arena, node->root);
  node->reap = root->reap;
  root->reap = id_of(arena, node);
}

// Uncharges `bytes` from `node`. A live quota keeps them (its parent paid
// for its whole limit up front). A closed quota passes them up to the first
// live one, and is queued for `reap` once nothing is charged to it.
void refund(Capability arena, Node* node, uint64_t bytes) {
  if (bytes == 0) {
    return;
  }
  for (;;) {
    node->account.used -= bytes;
    if (node->state != NODE_CLOSED) {
      return;
    }
    if (node->account.used == 0) {
      to_reap(arena, node);
    }
    node = node_of(arena, node->parent);  // a closed quota has one
  }
}

// Closes `top` and every quota below it, parents first. Each unused limit
// goes back to `top`'s parent at once; what is charged stays charged.
void close_subtree(Capability arena, Node* top) {
  Node* node = top;
  for (;;) {
    if (node->state == NODE_LIVE) {
      const uint64_t unused = node->account.limit - node->account.used;
      node->state = NODE_CLOSED;
      refund(arena, node_of(arena, node->parent), unused);
      if (node->account.used == 0) {
        to_reap(arena, node);
      }
    }
    if (node->child != 0) {
      node = node_of(arena, node->child);
      continue;
    }
    while (node != top && node->next == 0) {
      node = node_of(arena, node->parent);
    }
    if (node == top) {
      return;
    }
    node = node_of(arena, node->next);
  }
}

// What a quota handle names, as far as can be told without the lock.
struct Target {
  Slot* slot;
  uint64_t seen;     // the Slot's state when it was found
  uint64_t address;  // of the node
  uint64_t rights;   // the handle's permissions
};

// Opens a quota handle: HEAP_INVALID unless sealed here, for a live heap.
int64_t open_quota(Capability handle, Target* target) {
  const Capability node = sealing::unseal_with(s_auth_quota, handle);
  if (!capability_is_valid(node) ||
      capability_get_length(node) != sizeof(Node) ||
      capability_get_base(node) != capability_get_address(node) ||
      (capability_get_base(node) & (alignof(Node) - 1)) != 0) {
    return init::HEAP_INVALID;
  }
  target->address = capability_get_base(node);
  target->rights = capability_get_perms(node);
  target->slot = find(target->address, &target->seen);
  return target->slot != nullptr ? init::HEAP_OK : init::HEAP_INVALID;
}

// With the heap's lock held: the live quota `handle` names, or null. The
// tag is read again (heap.hpp, `tagged_now`): once the node is freed and
// swept its memory may be reused, but the handle is then untagged. While
// it is tagged, `state` is NODE_LIVE only for a live quota.
Node* live_node(const Target& target, Capability handle) {
  if (!heap::tagged_now(handle) || !same(*target.slot, target.seen) ||
      target.address + sizeof(Node) > target.slot->top) {
    return nullptr;
  }
  Node* node = node_at(*target.slot, target.address);
  return node->state == NODE_LIVE ? node : nullptr;
}

// Frees the nodes queued by `to_reap`, unlinking each from its parent. Each
// free may move chunks out of quarantine and queue more nodes. Entry points
// that used the allocator call this before leaving the heap.
void reap(Slot& slot, heap::Heap::Session& in) {
  const Capability arena = slot.arena;
  Node* root = node_at(slot, load(&slot.root));
  while (root->reap != 0) {
    const uint32_t id = root->reap;
    Node* node = node_of(arena, id);
    root->reap = node->reap;
    Node* parent = node_of(arena, node->parent);
    if (node->prev != 0) {
      node_of(arena, node->prev)->next = node->next;
    } else {
      parent->child = node->next;
    }
    if (node->next != 0) {
      node_of(arena, node->next)->prev = node->prev;
    }
    in.free(in.block_at(slot.base + (uint64_t{id} << OWNER_SHIFT)));
  }
}

// Why a heap could not be entered, as a status.
int64_t not_entered(heap::Why why) {
  if (why == heap::Why::Busy) {
    return init::HEAP_BUSY;
  }
  if (why == heap::Why::Unusable) {
    return init::HEAP_BROKEN;
  }
  return init::HEAP_INVALID;  // no heap any more
}

// Why a request was not granted, as a status.
int64_t not_granted(heap::Why why) {
  switch (why) {
    case heap::Why::Granted:
      return init::HEAP_OK;
    case heap::Why::TooBig:
      return init::HEAP_TOO_BIG;
    case heap::Why::NeedsSweep:
      return init::HEAP_NEEDS_SWEEP;
    case heap::Why::OverBudget:
      return init::HEAP_OVER_QUOTA;
    case heap::Why::Busy:
      return init::HEAP_BUSY;
    case heap::Why::Unusable:
      return init::HEAP_BROKEN;
    case heap::Why::Full:
      break;
  }
  return init::HEAP_NO_MEMORY;
}

// Whether the caller's `out` can take `bytes` bytes at its address, which
// must be a multiple of `align`, through a store that needs `need`.
bool can_store(Capability out, size_t bytes, size_t align, uint64_t need) {
  if (!capability_is_valid(out) || sealing::is_sealed(out) ||
      !capability_has_perms(out, need)) {
    return false;
  }
  const uint64_t address = capability_get_address(out);
  const uint64_t base = capability_get_base(out);
  const uint64_t length = capability_get_length(out);
  return (address & (align - 1)) == 0 && address >= base &&
         address - base <= length && length - (address - base) >= bytes;
}

// Asks for a sweep unless one is already under way. A freed arena goes back
// to the VM quota that paid for it only after a sweep has covered it.
void ask_for_sweep() {
  heap::core::revoker.query();
  heap::core::revoker.system_bg_revoker_kick();
}

// Gives the arena of a Slot this thread made SLOT_BUSY back to the VM quota
// that paid for it, and frees the Slot. The service holds nothing into the
// arena by now; the next sweep kills what clients still hold.
void give_back(Slot& slot, uint64_t busy) {
  const Capability arena = slot.arena;
  const Capability vm_quota = slot.vm_quota;
  slot.arena = nullptr;
  slot.vm_quota = nullptr;
  store(&slot.base, 0);
  store(&slot.top, 0);
  store(&slot.root, 0);
  using FnDealloc = decltype(&sys_vm_deallocate);
  syscall::call<FnDealloc>(s_invoke, s_vm_dealloc, s_self, vm_quota, arena);
  ask_for_sweep();
  store(&slot.state, (busy & ~SLOT_PHASE) + SLOT_NEXT + SLOT_FREE);
}

}  // namespace

// A chunk has left quarantine (heap.hpp, WHO PAYS): refund its quota. A
// child quota's node refunds its parent (`node_of` drops NODE_CHUNK). Owners
// up to `OWNER` (the allocator's and the service's own chunks, root quota
// nodes among them) are charged to nobody. Called with the heap's lock held.
void heap::released(Capability arena, uint32_t owner, size_t bytes) {
  if (owner <= heap::OWNER) {
    return;
  }
  refund(arena, node_of(arena, owner), bytes);
}

// `heap.create`: a heap of `bytes` bytes paid for by `vm_quota`; returns its
// root quota handle, with both rights. If the quota cannot pay, asks for a
// sweep (one may refund it) and returns HEAP_NO_MEMORY.
extern "C" Capability heap_create_entry(Capability vm_quota, size_t bytes) {
  if (!sealing::is_sealed_as(OType::QuotaVm, vm_quota)) {
    return init::status_cap(init::HEAP_INVALID);
  }
  if (bytes == 0 || bytes > init::HEAP_MAX_BYTES) {
    return init::status_cap(init::HEAP_BAD_REQUEST);
  }
  Slot* slot = nullptr;
  uint64_t busy = 0;
  for (Slot& candidate : s_slots) {
    const uint64_t state = load(&candidate.state);
    if ((state & SLOT_PHASE) == SLOT_FREE &&
        swap(&candidate.state, state, state + SLOT_BUSY)) {
      slot = &candidate;
      busy = state + SLOT_BUSY;
      break;
    }
  }
  if (slot == nullptr) {
    return init::status_cap(init::HEAP_FULL);
  }

  // Revocable, so that the heap can take freed blocks back, and zeroed,
  // which the heap's `init` needs. The memory is this compartment's.
  using FnAlloc = decltype(&sys_vm_allocate);
  const Capability arena = syscall::call<FnAlloc>(
      s_invoke, s_vm_alloc, s_self, vm_quota, bytes, FLAG_REVOCABLE);
  if (!capability_is_valid(arena)) {
    store(&slot->state, busy - SLOT_BUSY);
    ask_for_sweep();
    return init::status_cap(init::HEAP_NO_MEMORY);
  }
  slot->arena = arena;
  slot->vm_quota = vm_quota;
  store(&slot->base, capability_get_base(arena));
  store(&slot->top,
        capability_get_base(arena) + capability_get_length(arena));

  // The root quota's node is the heap's first block: the service's own,
  // charged to nobody. The root's limit is all that is then free.
  Capability handle = nullptr;
  if (capability_get_length(arena) <= init::HEAP_MAX_BYTES &&
      slot->heap.init(arena)) {
    heap::Heap::Session in(slot->heap);
    if (!in) {
      // Not reached: nobody else can have entered a heap made just now.
      // The Slot is left busy for good, and the arena is given back.
      using FnDealloc = decltype(&sys_vm_deallocate);
      syscall::call<FnDealloc>(s_invoke, s_vm_dealloc, s_self, vm_quota,
                               arena);
      slot->arena = nullptr;
      slot->vm_quota = nullptr;
      return init::status_cap(init::HEAP_BAD_REQUEST);
    }
    const Capability block = in.allocate(sizeof(Node), heap::OWNER, nullptr);
    if (capability_is_valid(block)) {
      Node* root = reinterpret_cast<Node*>(block);
      root->account.limit = in.free_size();
      root->account.used = 0;
      root->state = NODE_LIVE;
      root->root = owner_of(*slot, capability_get_address(block));
      store(&slot->root, capability_get_address(block));
      handle = seal_quota(*slot, capability_get_address(block), QUOTA_RIGHTS);
    }
    if (capability_is_valid(handle)) {
      store(&slot->state, busy - SLOT_BUSY + SLOT_LIVE);
    } else {
      in.retire();
    }
  }
  if (!capability_is_valid(handle)) {
    give_back(*slot, busy);  // too small to be a heap
    return init::status_cap(init::HEAP_BAD_REQUEST);
  }
  return handle;
}

// `heap.alloc`: a block of at least `size` bytes charged to `quota` (needs
// Permit_Load), stored through `out`; returns its handle. A refusal
// allocates and stores nothing.
extern "C" Capability heap_alloc_entry(Capability quota, size_t size,
                                       Capability out) {
  if (!can_store(out, sizeof(Capability), alignof(Capability),
                 perms::Store | perms::StoreCapability)) {
    return init::status_cap(init::HEAP_BAD_REQUEST);
  }
  Target target;
  const int64_t status = open_quota(quota, &target);
  if (status != init::HEAP_OK) {
    return init::status_cap(status);
  }
  if ((target.rights & perms::Load) == 0) {
    return init::status_cap(init::HEAP_PERMISSION);
  }
  Capability block = nullptr;
  heap::Refusal refusal = {heap::Why::Granted, 0};
  {
    heap::Heap::Session in(target.slot->heap);
    if (!in) {
      return init::status_cap(not_entered(in.refused()));
    }
    Node* node = live_node(target, quota);
    if (node == nullptr) {
      return init::status_cap(init::HEAP_INVALID);
    }
    block = in.allocate(size, owner_of(*target.slot, target.address),
                        &node->account, &refusal);
    reap(*target.slot, in);
  }
  if (!capability_is_valid(block)) {
    return init::status_cap(not_granted(refusal.why));
  }
  const Capability handle =
      sealing::seal_with(s_auth_alloc, capability_and_perms(block, 0));
  // Outside the lock. If this store faults anyway (say `out` was revoked
  // meanwhile), the block stays allocated and charged: the caller's loss.
  *reinterpret_cast<Capability*>(out) = block;
  return handle;
}

// `heap.free`: frees the block of allocation handle `handle`. Its quota
// stays charged until the block is swept.
extern "C" int64_t heap_free_entry(Capability handle) {
  const Capability block = sealing::unseal_with(s_auth_alloc, handle);
  if (!capability_is_valid(block)) {
    return init::HEAP_INVALID;
  }
  uint64_t seen = 0;
  Slot* slot = find(capability_get_base(block), &seen);
  if (slot == nullptr) {
    return init::HEAP_INVALID;
  }
  heap::Heap::Session in(slot->heap);
  if (!in) {
    return not_entered(in.refused());
  }
  if (!same(*slot, seen) || !in.free(block)) {
    return init::HEAP_INVALID;
  }
  reap(*slot, in);
  return init::HEAP_OK;
}

// `heap.destroy` (needs Permit_Store): closes a child quota and all below it
// (THE TREE OF QUOTAS) and frees their blocks; or, for a root quota, ends
// the heap, even a HEAP_BROKEN one.
extern "C" int64_t heap_destroy_entry(Capability quota) {
  Target target;
  const int64_t status = open_quota(quota, &target);
  if (status != init::HEAP_OK) {
    return status;
  }
  if ((target.rights & perms::Store) == 0) {
    return init::HEAP_PERMISSION;
  }
  Slot& slot = *target.slot;
  if (load(&slot.root) != target.address) {
    heap::Heap::Session in(slot.heap);
    if (!in) {
      return not_entered(in.refused());
    }
    Node* node = live_node(target, quota);
    if (node == nullptr || node->parent == 0) {
      return init::HEAP_INVALID;
    }
    const Capability arena = slot.arena;
    close_subtree(arena, node);
    // Free every block of a closed quota. Node chunks (NODE_CHUNK) are left
    // to `reap`, which frees each once nothing is charged to it.
    in.free_where([arena](uint32_t owner) {
      return (owner & NODE_CHUNK) == 0 &&
             node_of(arena, owner)->state == NODE_CLOSED;
    });
    reap(slot, in);
    return init::HEAP_OK;
  }
  // A root. Its Slot goes from live to busy, so nobody finds the heap again
  // and only one thread can do it. From inside the heap, so nobody else is
  // in it and threads waiting for the lock find no heap when they get in.
  const uint64_t busy = target.seen - SLOT_LIVE + SLOT_BUSY;
  bool claimed = false;
  if (!slot.heap.broken()) {
    heap::Heap::Session in(slot.heap);
    if (in) {
      if (!heap::tagged_now(quota) || !swap(&slot.state, target.seen, busy)) {
        return init::HEAP_INVALID;
      }
      in.retire();
      claimed = true;
    } else if (in.refused() != heap::Why::Unusable) {
      return not_entered(in.refused());
    }
  }
  if (!claimed) {
    // Broken: nobody is in the heap and nobody can enter it. The arena is
    // not read; `slot.root` showed that the handle is the root's.
    if (!swap(&slot.state, target.seen, busy)) {
      return init::HEAP_INVALID;
    }
    slot.heap.retire_broken();
  }
  give_back(slot, busy);
  return init::HEAP_OK;
}

// `heap.derive` (needs Permit_Store): a child of `parent` with limit `bytes`
// and those of `rights` that `parent` has. The parent pays at once for
// `bytes` and the node (THE TREE OF QUOTAS). Returns the child's handle.
extern "C" Capability heap_derive_entry(Capability parent, size_t bytes,
                                        uint64_t rights) {
  Target target;
  const int64_t status = open_quota(parent, &target);
  if (status != init::HEAP_OK) {
    return init::status_cap(status);
  }
  if ((target.rights & perms::Store) == 0) {
    return init::status_cap(init::HEAP_PERMISSION);
  }
  const uint64_t granted = rights & target.rights & QUOTA_RIGHTS;
  if (bytes == 0 || granted == 0) {
    return init::status_cap(init::HEAP_BAD_REQUEST);
  }
  Slot& slot = *target.slot;
  heap::Heap::Session in(slot.heap);
  if (!in) {
    return init::status_cap(not_entered(in.refused()));
  }
  Node* above = live_node(target, parent);
  if (above == nullptr) {
    return init::status_cap(init::HEAP_INVALID);
  }
  // All or nothing: the parent must cover the limit and the node's highest
  // cost. If it is short, first reclaim what completed sweeps allow.
  auto short_of = [&] {
    const uint64_t left = above->account.used < above->account.limit
                              ? above->account.limit - above->account.used
                              : 0;
    return bytes > left || left - bytes < init::HEAP_NODE_COST_MAX;
  };
  if (short_of()) {
    in.reclaim(true);
    reap(slot, in);
    if (short_of()) {
      return init::status_cap(init::HEAP_OVER_QUOTA);
    }
  }
  // The node: a block of the heap in the parent's name, marked as a node.
  const uint32_t above_id = owner_of(slot, target.address);
  heap::Refusal refusal = {heap::Why::Granted, 0};
  const Capability block = in.allocate(sizeof(Node), above_id | NODE_CHUNK,
                                       &above->account, &refusal);
  Capability handle = init::status_cap(not_granted(refusal.why));
  if (capability_is_valid(block)) {
    Node* node = reinterpret_cast<Node*>(block);
    const uint32_t id = owner_of(slot, capability_get_address(block));
    node->account.limit = bytes;
    node->account.used = 0;
    node->parent = above_id;
    node->root = above->root;
    node->next = above->child;
    if (above->child != 0) {
      node_of(slot.arena, above->child)->prev = id;
    }
    above->child = id;
    above->account.used += bytes;
    node->state = NODE_LIVE;
    handle = seal_quota(slot, capability_get_address(block), granted);
  }
  reap(slot, in);
  return handle;
}

// `heap.reclaim`: takes every swept block of `quota`'s heap out of
// quarantine (refunding its quota) and asks for a sweep if any are left.
// Returns the bytes still in quarantine in the whole heap.
extern "C" int64_t heap_reclaim_entry(Capability quota) {
  Target target;
  const int64_t status = open_quota(quota, &target);
  if (status != init::HEAP_OK) {
    return status;
  }
  heap::Heap::Session in(target.slot->heap);
  if (!in) {
    return not_entered(in.refused());
  }
  if (live_node(target, quota) == nullptr) {
    return init::HEAP_INVALID;
  }
  in.reclaim(true);
  reap(*target.slot, in);
  return static_cast<int64_t>(in.quarantined_size());
}

// `heap.info`: stores `quota`'s HeapInfo (abi.hpp) through `out`. The heap
// count is read without a lock, so it may be out of date.
extern "C" int64_t heap_info_entry(Capability quota, Capability out) {
  if (!can_store(out, sizeof(init::HeapInfo), alignof(init::HeapInfo),
                 perms::Store)) {
    return init::HEAP_BAD_REQUEST;
  }
  Target target;
  const int64_t status = open_quota(quota, &target);
  if (status != init::HEAP_OK) {
    return status;
  }
  uint64_t limit = 0;
  uint64_t used = 0;
  uint64_t contended = 0;
  {
    heap::Heap::Session in(target.slot->heap);
    if (!in) {
      return not_entered(in.refused());
    }
    const Node* node = live_node(target, quota);
    if (node == nullptr) {
      return init::HEAP_INVALID;
    }
    limit = node->account.limit;
    used = node->account.used;
    contended = target.slot->heap.contended();
  }
  uint64_t heaps = 0;
  for (const Slot& slot : s_slots) {
    if ((load(&slot.state) & SLOT_PHASE) == SLOT_LIVE) {
      heaps += 1;
    }
  }
  // Outside the lock, as in `heap_alloc_entry`.
  auto* info = reinterpret_cast<init::HeapInfo*>(out);
  info->limit = limit;
  info->used = used;
  info->heaps = heaps;
  info->contended = contended;
  return init::HEAP_OK;
}

// How long `heap.wait` sleeps between two looks at quarantine.
constexpr uint64_t WAIT_STEP_US = 2'000;

// `heap.wait`: `heap.reclaim`, then sleeps WAIT_STEP_US at a time until less
// is in quarantine or `timeout_us` (at most HEAP_WAIT_MAX_US) has passed. It
// sleeps holding no heap's lock, so a killed caller ends outside every heap.
extern "C" int64_t heap_wait_entry(Capability quota, uint64_t timeout_us) {
  const int64_t before = heap_reclaim_entry(quota);
  if (before <= 0) {
    return before;  // nothing is in quarantine, or a status
  }
  const uint64_t limit = timeout_us < init::HEAP_WAIT_MAX_US
                             ? timeout_us
                             : init::HEAP_WAIT_MAX_US;
  for (uint64_t slept = 0; slept < limit; slept += WAIT_STEP_US) {
    if (invoke<int64_t>(s_invoke, s_sched_block, WAIT_STEP_US) ==
        init::SCHED_KILLED) {
      break;  // a killed thread does not sleep: let it go
    }
    const int64_t now = heap_reclaim_entry(quota);
    if (now < before) {
      return now;  // something came back, or a status
    }
  }
  return before;
}

SIGNETOS_DEFAULT_FAULT_HANDLER("heap")

namespace {

// True if `authority` is the sealing authority over `type` and nothing
// else: tagged, unsealed, with Seal and Unseal, naming exactly that type.
bool authority_ok(Capability authority, OType type) {
  return capability_is_valid(authority) && !sealing::is_sealed(authority) &&
         capability_has_perms(authority, perms::Seal | perms::Unseal) &&
         capability_get_base(authority) == static_cast<uint64_t>(type) &&
         capability_get_address(authority) == static_cast<uint64_t>(type) &&
         capability_get_length(authority) == 1;
}

// Mints an entry point over `fn`, publishes it as `name` and records it in
// the table at `slot`. False if either fails.
bool publish(Capability* rw, const char* name, const void* fn, size_t slot) {
  const Capability gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  const Capability gate_sentry = rw[SLOT_SYS_SENTRY];
  const Capability entry =
      sealing::is_sealed_as(OType::EntryPoint, gate_sentry)
          ? mint_entry(gate_invoke, gate_sentry, rw[compartment::SLOT_SELF], fn)
          : nullptr;
  if (!sealing::is_sealed_as(OType::EntryPoint, entry) ||
      publish_name(gate_invoke, rw[SLOT_NAMING_PUBLISH], name, entry) !=
          init::NAMING_OK) {
    return false;
  }
  rw[slot] = entry;
  return true;
}

}  // namespace

extern "C" int64_t compartment_main(Capability arg) {
  (void)arg;  // nothing is handed over, and nothing back
  Capability* rw = rw_table();

  const Capability self_comp = rw[compartment::SLOT_SELF];
  const Capability gate_alloc = rw[SLOT_SYS_VM_ALLOC];
  const Capability gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  const Capability uart_sentry = rw[SLOT_UART_SENTRY];

  if (s_online) {
    return -1;  // set up once, by `init`
  }
  if (!sealing::is_sealed_as(OType::Compartment, self_comp) ||
      !sealing::is_sealed_as(OType::EntryPoint, gate_alloc) ||
      !sealing::is_entry(gate_invoke)) {
    return -1;
  }

  // `heap::setup` checks the gates, the scheduler's lock entries included.
  heap::RevokeGates gates;
  gates.invoke = gate_invoke;
  gates.self = self_comp;
  gates.revoke = rw[SLOT_SYS_REVOKE];
  gates.revoke_query = rw[SLOT_SYS_REVOKE_QUERY];
  gates.revoke_start = rw[SLOT_SYS_REVOKE_START];
  heap::LockGates locks;
  locks.invoke = gate_invoke;
  locks.lock_wait = rw[SLOT_SCHED_LOCK_WAIT];
  locks.lock_wake = rw[SLOT_SCHED_LOCK_WAKE];
  if (!heap::setup(gates, &locks)) {
    print(gate_invoke, uart_sentry,
          "[heap]     WARNING: could not set up the revocation or lock "
          "gates\n");
    return -1;
  }
  s_online = true;

  // Clients' heaps: the authorities, the gates the entries use, the entries.
  s_auth_quota = rw[SLOT_SEAL_QUOTA];
  s_auth_alloc = rw[SLOT_SEAL_ALLOC];
  s_invoke = gate_invoke;
  s_self = self_comp;
  s_vm_alloc = gate_alloc;
  s_vm_dealloc = rw[SLOT_SYS_VM_DEALLOC];
  s_sched_block = rw[SLOT_SCHED_BLOCK];
  if (!authority_ok(s_auth_quota, OType::QuotaHeap) ||
      !authority_ok(s_auth_alloc, OType::HeapAllocation) ||
      !sealing::is_sealed_as(OType::EntryPoint, s_vm_dealloc) ||
      !sealing::is_sealed_as(OType::EntryPoint, s_sched_block) ||
      !publish(rw, "heap.create",
               reinterpret_cast<const void*>(&heap_create_entry),
               SLOT_ENTRY_BASE + 0) ||
      !publish(rw, "heap.alloc",
               reinterpret_cast<const void*>(&heap_alloc_entry),
               SLOT_ENTRY_BASE + 1) ||
      !publish(rw, "heap.free",
               reinterpret_cast<const void*>(&heap_free_entry),
               SLOT_ENTRY_BASE + 2) ||
      !publish(rw, "heap.destroy",
               reinterpret_cast<const void*>(&heap_destroy_entry),
               SLOT_ENTRY_BASE + 3) ||
      !publish(rw, "heap.reclaim",
               reinterpret_cast<const void*>(&heap_reclaim_entry),
               SLOT_ENTRY_BASE + 4) ||
      !publish(rw, "heap.info",
               reinterpret_cast<const void*>(&heap_info_entry),
               SLOT_ENTRY_BASE + 5) ||
      !publish(rw, "heap.derive",
               reinterpret_cast<const void*>(&heap_derive_entry),
               SLOT_ENTRY_BASE + 6) ||
      !publish(rw, "heap.wait",
               reinterpret_cast<const void*>(&heap_wait_entry),
               SLOT_ENTRY_BASE + 7)) {
    s_auth_quota = nullptr;
    s_auth_alloc = nullptr;
    print(gate_invoke, uart_sentry,
          "[heap]     WARNING: a sealing authority or `sched.block` is "
          "missing, or an entry point could not be minted or published\n");
    return -1;
  }
  LineBuffer published;
  published.str("[heap]     Heap service online: heap.* published, up to ");
  published.dec(init::HEAP_MAX_HEAPS);
  published.str(" heaps\n");
  print(gate_invoke, uart_sentry, published.buf);
  return 0;
}

}  // namespace signetos::user

#if defined(SIGNETOS_HEAP_DEBUG)
// Prints a failed allocator check (user/heap/heap_compat.hpp). It may run
// anywhere in the allocator, so it takes the console from the table.
void signetos_heap_debug_write(const char* line) {
  const ::signetos::Capability* rw = ::signetos::user::rw_table();
  ::signetos::user::print(rw[::signetos::user::SLOT_SYS_COMP_INVOKE],
                          rw[::signetos::user::SLOT_UART_SENTRY], line);
}
#endif
