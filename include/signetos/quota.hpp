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
// quota.hpp - SignetOS Hierarchical Quota Trees
//
// One implementation serves every quota kind. A `Tree` is a static root node
// plus page-backed descendants, all sealed with the tree's own `OType`, so a
// handle from one tree can never authenticate against another. The VM tree
// lives here; the thread-memory tree is instantiated by `thread.cpp`.
//
// Quotas are IMMUTABLE once derived: a budget cannot be resized or
// renegotiated. The only transition out of a fixed budget is destruction.
//
// ONE LEDGER
//
// A node has an allowance (`limit_bytes`) and a record of what it has handed
// out of it (`allocated_bytes`): to allocations, to threads, and to each child
// node, which counts for the child's allowance plus the cost of the child's
// page. A child is therefore nothing more than an allocation its parent made,
// and giving allowance back up the tree is the same operation as refunding an
// allocation into a node: `refund` and `refund_unused` move the same counter.
//
// DESTROY CLOSES, IT DOES NOT KILL
//
// Destroying a node never waits for it to be empty and never touches what it
// paid for. It CLOSES the node AND EVERY NODE BENEATH IT: no handle can
// charge, derive or destroy through any of them again. A budget is a tree, so
// a child's headroom is part of the parent's; leaving it open would let it
// keep consuming bytes the parent has taken back, through handles the parent
// cannot see. Everything the subtree funded -- allocations, threads -- carries
// on and still refunds into it.
//
// A CLOSED NODE NEVER HOLDS UNUSED ALLOWANCE. Whatever it is not using goes
// to its parent: all of it the moment it is closed, and the rest refund by
// refund as its outstanding allocations come back, passing straight through
// closed ancestors to the first live one. Once a closed node holds nothing it
// is RECLAIMED: its page is freed and the last of its allowance, by then
// exactly QUOTA_NODE_COST, goes back as well. Killing what a quota paid for
// is compartment and thread destruction, not this.
//
// WHERE NODES LIVE
//
// Each derived node occupies one page, billed to the parent that asked for it.
// There is no pool, no free list and no slot recycling. A reclaimed node's page
// is quarantined (vm.hpp): it stays mapped, so its handles still reach it, and
// they are refused because its flags are clear. The revocation sweep will
// eventually clear their tags too.
//
// Root nodes are the exception. They have no parent to bill, so each tree's
// single root node lives in .bss.
//
// AUTHENTICATION VS ACCESS
//
// A handle is authenticated by `yunseal` under the tree's OType, which only the
// kernel can perform. The unsealed view carries the CALLER's delegated
// permissions, so it proves genuineness but is used only to read `self_page`:
// the writable kernel capability to the node that the kernel stored there.
//
// Delegated authority is carried by the handle's hardware permissions:
//   Permit_Load  -> operational authority     (charge / refund / fund threads)
//   Permit_Store -> administrative authority  (derive children / destroy)
//
// LOCKING
//
// Every node has its own lock and nothing locks a whole tree, so there is no
// lock that every holder of a quota has to get through. Charge, refund, query
// and derive lock one node: the node itself, or for derive the parent. Two
// things go from node to node:
//
//   - Allowance a closed node gives back goes up one node at a time. The node
//     gives it back under its own lock and lets go; then the parent takes it
//     back under the parent's lock, and passes it on the same way if it is
//     closed too. The parent cannot be freed in between: until it has taken
//     the bytes back it still counts them as handed out, so it is not empty.
//   - Destroy walks down the subtree holding the lock of every node on its
//     path, from the destroyed node to wherever it has got to, so nothing on
//     that path can be unlinked or freed under it. Outside the subtree it
//     locks only the ancestors its unused allowance goes up through, one at a
//     time, like a refund.
//
// Two locks are only ever held together parent first, so they cannot
// deadlock. A node is freed by whichever operation empties it: clearing
// FLAG_EXISTS under the node's lock claims it, and since every operation
// refuses a node without that flag, exactly one caller goes on to unlink it,
// under the parent's lock, and free it.
//
// Destroy returns once everything unused in the subtree is with the parent,
// apart from bytes that a refund or destroy running on another hart has
// already picked up and is still carrying; those arrive before that
// operation returns.
//
// `vm::alloc_pages` is never called with a node lock held: it can run a
// revocation sweep, which refunds into the tree.
//

#include <stdint.h>
#include <stddef.h>
#include <signetos/lock.hpp>
#include <signetos/types.hpp>
#include <signetos/vm.hpp>

namespace signetos::quota {

// One page, the allocation granularity of sys_vm_allocate. Stated in PAGES,
// with the byte cost derived, because `vm::alloc_pages` counts pages and the
// ledger counts bytes, and the two must not drift apart.
constexpr size_t   QUOTA_NODE_PAGES = 1;
constexpr uint64_t QUOTA_NODE_COST  = QUOTA_NODE_PAGES * vm::PAGE_SIZE;

constexpr uint32_t FLAG_ROOT = (1u << 0);
// Set until the node is destroyed (closed), directly or as part of an
// ancestor's subtree. This is what makes a closed node's handles fail: they
// still unseal and still reach the node, so only this flag says it is closed.
// Charge, derive, destroy and query require it. Safe to keep in the node
// because callers never obtain a writable capability to it.
constexpr uint32_t FLAG_LIVE = (1u << 1);
// Set until the node is reclaimed. Refunds require only this, so a closed node
// keeps taking refunds until nothing is outstanding. Cleared under the node's
// lock by the operation that empties it, which claims the node: that
// operation, and only that one, unlinks and frees it (LOCKING above).
constexpr uint32_t FLAG_EXISTS = (1u << 2);

using Status = signetos::Status;
using signetos::status_name;

// `self_page` must stay at offset 0. `lock` protects the counters, the flags
// and `first_child`. A node's sibling links are part of its parent's child
// list, so the parent's lock protects those. `parent` is set before the node
// is linked and stays put until it is unlinked, under the parent's lock.
struct QuotaNode {
    Capability self_page;     // writable kernel capability to this node's page
    QuotaNode* parent;        // null for the root
    QuotaNode* first_child;
    QuotaNode* next_sibling;
    QuotaNode* prev_sibling;

    uint64_t limit_bytes;     // allowance: fixed at derive, shrinks only as a
                              // closed node refunds what it is not using
    uint64_t allocated_bytes; // handed out: allocations, threads, and each
                              // child as its limit + QUOTA_NODE_COST
    uint32_t flags;
    SpinLock lock;

    // Conservation invariant: allocated_bytes <= limit_bytes. Nothing handed
    // out costs less than a page, so a node with allocated_bytes == 0 has no
    // children and no threads either.
    uint64_t available() const {
        return (allocated_bytes >= limit_bytes) ? 0
                                                : (limit_bytes - allocated_bytes);
    }
};

using QuotaVm = QuotaNode;

static_assert(sizeof(QuotaNode) <= QUOTA_NODE_COST,
              "a quota node must fit in one page");

// A quota tree: the OType its handles are sealed with, its static root, and
// how many nodes it has. There is no lock for the tree as a whole (LOCKING
// above).
struct Tree {
    OType type;
    QuotaNode root;
    bool root_taken;
    size_t live_nodes;        // updated atomically
};

// --- Generic operations on any tree -----------------------------------------

// Resets `t`. Requires the sealing authority for `t.type`.
void init(Tree& t, OType type);

// Unseals `handle` under `t`'s type and returns the node, or null if it is not
// genuine or the node has been freed. A closed node is returned: operations
// that need it open check FLAG_LIVE under the node's lock.
QuotaNode* unseal(Tree& t, Capability handle);

// Boot-time root. Occupies the static root node, costs no frames. Returns a
// handle with both operational and administrative authority, or null if a root
// already exists.
Capability create_root(Tree& t, uint64_t total_bytes);

// Derives an immutable child budget. Debits `amount_bytes + QUOTA_NODE_COST`
// from the parent and funds the child's node from the frame allocator.
// Requires Permit_Store on the parent.
Capability derive(Tree& t, Capability parent_handle, uint64_t amount_bytes,
                  uint64_t perms_mask, Status* out_status = nullptr);

// Closes a quota and its whole subtree (DESTROY CLOSES, IT DOES NOT KILL
// above): clears FLAG_LIVE on every node in it and gives every unused byte in
// it back to the parent at once. The rest follows refund by refund as what is
// outstanding comes back; a node with nothing outstanding is freed at once.
// Requires Permit_Store. Fails only for a bad or closed handle, or the root.
Status destroy(Tree& t, Capability handle);

// Charges / credits bytes. Requires Permit_Load. Refund also accepts a closed
// node; what a closed node is credited passes straight on to its parent, and
// the node is reclaimed once it holds nothing.
Status charge(Tree& t, Capability handle, uint64_t bytes);
Status refund(Tree& t, Capability handle, uint64_t bytes);

// Kernel-internal introspection. False if the handle is not genuine.
bool query(Tree& t, Capability handle, QuotaNode* out_copy);

// --- The VM quota tree (OType::QuotaVm) --------------------------------------

Tree& vm_tree();

void init();

inline Capability create_root(uint64_t total_system_bytes) {
    return create_root(vm_tree(), total_system_bytes);
}
inline Capability derive(Capability parent_handle, uint64_t amount_bytes,
                         uint64_t perms_mask, Status* out_status = nullptr) {
    return derive(vm_tree(), parent_handle, amount_bytes, perms_mask, out_status);
}
inline Status destroy(Capability handle) { return destroy(vm_tree(), handle); }
inline Status charge(Capability handle, uint64_t bytes) {
    return charge(vm_tree(), handle, bytes);
}
inline Status refund(Capability handle, uint64_t bytes) {
    return refund(vm_tree(), handle, bytes);
}
inline bool query(Capability handle, QuotaVm* out_copy) {
    return query(vm_tree(), handle, out_copy);
}
inline size_t live_nodes() {
    return __atomic_load_n(&vm_tree().live_nodes, __ATOMIC_RELAXED);
}

#ifdef SIGNETOS_QUOTA_SELFTEST
// Boot-time check of destroy, refund and reclaim against a scratch subtree of
// `root` (QUOTA_SELFTEST=1). Panics on the first failure.
void self_test(Capability root);
#endif


} // namespace signetos::quota
