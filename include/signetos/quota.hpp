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
// renegotiated. The only transition out of a fixed budget is destruction, which
// refunds the full allowance to the parent in O(1).
//
// WHERE NODES LIVE
//
// Each derived node occupies one page, billed to the parent that asked for it.
// There is no pool, no free list and no slot recycling. A destroyed node's page
// is quarantined (vm.hpp): it stays mapped, so its handles still reach it, and
// they are refused because destroy cleared FLAG_LIVE. The revocation sweep will
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
// Set while the node is in use, cleared on destroy. This is what makes a stale
// handle fail: a destroyed node's page is quarantined, not unmapped, so the
// handle still unseals and still reaches the node. Only this flag says it is
// dead. Safe to keep in the node because callers never obtain a writable
// capability to it.
constexpr uint32_t FLAG_LIVE = (1u << 1);

using Status = signetos::Status;
using signetos::status_name;

// `self_page` must stay at offset 0.
struct QuotaNode {
    Capability self_page;     // writable kernel capability to this node's page
    Capability parent;        // sealed handle to parent (nullptr for root)
    QuotaNode* first_child;
    QuotaNode* next_sibling;
    QuotaNode* prev_sibling;
    uint64_t child_count;

    uint64_t limit_bytes;     // immutable total budget
    uint64_t allocated_bytes; // bytes charged against this node
    uint64_t delegated_bytes; // sum of (limit + QUOTA_NODE_COST) given to children
    uint32_t active_threads;  // thread-memory trees: threads funded by this node
    uint32_t flags;
    SpinLock lock;            // protects ledger counters and child list

    // Conservation invariant: allocated_bytes + delegated_bytes <= limit_bytes
    uint64_t available() const {
        const uint64_t used = allocated_bytes + delegated_bytes;
        return (used >= limit_bytes) ? 0 : (limit_bytes - used);
    }
};

using QuotaVm = QuotaNode;

static_assert(sizeof(QuotaNode) <= QUOTA_NODE_COST,
              "a quota node must fit in one page");

// A quota tree: the OType its handles are sealed with, and its static root.
struct Tree {
    OType type;
    QuotaNode root;
    bool root_taken;
    size_t live_nodes;
};

// --- Generic operations on any tree -----------------------------------------

// Resets `t`. Requires the sealing authority for `t.type`.
void init(Tree& t, OType type);

// Unseals `handle` under `t`'s type and returns the live node, or null.
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

// Destroys a quota, refunding limit + QUOTA_NODE_COST to its parent in O(1),
// clearing FLAG_LIVE and quarantining its page. Requires Permit_Store, no
// children, nothing allocated, no active threads.
Status destroy(Tree& t, Capability handle);

// Charges / credits bytes. Requires Permit_Load.
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


} // namespace signetos::quota
