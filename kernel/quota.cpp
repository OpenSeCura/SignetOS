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
 * quota.cpp - SignetOS Hierarchical Quota Trees
 *
 * See quota.hpp for the node lifetime, locking and authentication model.
 */

#include <signetos/quota.hpp>
#include <signetos/sealing.hpp>

namespace signetos::quota {
namespace {

Tree s_vm_tree;

void init_node(QuotaNode* node, uint64_t limit_bytes, uint32_t flags) {
  node->self_page = nullptr;
  node->parent = nullptr;
  node->first_child = nullptr;
  node->next_sibling = nullptr;
  node->prev_sibling = nullptr;
  node->limit_bytes = limit_bytes;
  node->allocated_bytes = 0;
  node->flags = flags | FLAG_LIVE | FLAG_EXISTS;
  node->lock = SpinLock{};
}

// Seals a node as a handle of `t` carrying `perms_mask`. When `Permit_Load`
// is present, `LoadCapability | LoadMutable` are preserved on the sealed
// handle so the kernel can read `self_page` directly on unseal.
Capability seal_node(Tree& t, QuotaNode* node, uint64_t perms_mask) {
  Capability c = reinterpret_cast<Capability>(node);
  c = capability_set_bounds(c, sizeof(QuotaNode));
  uint64_t effective_perms = perms_mask;
  if ((effective_perms & perms::Load) != 0) {
    effective_perms |= perms::LoadCapability | perms::LoadMutable;
  }
  c = capability_and_perms(c, effective_perms);
  return sealing::seal_as(t.type, c);
}

// Call with `node->lock` held and `node` closed. A closed node never holds
// unused allowance: this lowers its limit to what it has handed out and
// returns the difference, which belongs to the parent again (take_back). If
// that leaves the limit at zero the node holds nothing at all, and clearing
// FLAG_EXISTS claims it: every operation refuses a node without that flag,
// so the caller is the only one that will ever free it.
uint64_t give_back(QuotaNode* node) {
  const uint64_t unused = node->available();
  node->limit_bytes -= unused;
  if (node->limit_bytes == 0) {
    node->flags &= ~FLAG_EXISTS;
  }
  return unused;
}

// Call with `parent->lock` held, once `child` has given back `unused`. Takes
// those bytes off what the parent has handed out. If give_back() emptied the
// child, it claimed it for this caller: the child is unlinked and the cost of
// its page comes off too, which completes the refund of the
// limit + QUOTA_NODE_COST the parent was charged at derive. Returns the
// child's page for free_node_page() if so, otherwise null.
Capability take_back(QuotaNode* parent, QuotaNode* child, uint64_t unused,
                     bool child_empty) {
  parent->allocated_bytes -= unused;
  if (!child_empty) {
    // `child` is not touched: since it gave back, another refund may have
    // emptied it and freed it.
    return nullptr;
  }

  if (child->prev_sibling != nullptr) {
    child->prev_sibling->next_sibling = child->next_sibling;
  } else {
    parent->first_child = child->next_sibling;
  }
  if (child->next_sibling != nullptr) {
    child->next_sibling->prev_sibling = child->prev_sibling;
  }
  parent->allocated_bytes -= QUOTA_NODE_COST;

  Capability page = child->self_page;
  child->self_page = nullptr;
  child->parent = nullptr;
  child->first_child = nullptr;
  child->next_sibling = nullptr;
  child->prev_sibling = nullptr;
  return page;
}

// Frees the page take_back() returned, if it returned one. The page is
// quarantined, not unmapped: handles held by other compartments keep reaching
// it until the revocation sweep, and are refused by the cleared flags and
// self_page, which unseal() checks.
void free_node_page(Tree& t, Capability page) {
  if (!capability_is_valid(page)) {
    return;
  }
  vm::free_pages(page);
  __atomic_fetch_sub(&t.live_nodes, 1, __ATOMIC_RELAXED);
}

// Call with `node->lock` held; returns with no lock held. A live node keeps
// what it has. A closed one gives its unused allowance to its parent, a closed
// parent passes it on the same way, and so on up to the first live ancestor,
// freeing on the way every node that is left holding nothing.
//
// One lock at a time (LOCKING in quota.hpp): each node gives back under its
// own lock and lets go before its parent takes back under the parent's.
// `parent` cannot be freed in between, because until take_back() it still
// counts what `node` gave back as handed out.
void refund_unused(Tree& t, QuotaNode* node) {
  while ((node->flags & FLAG_LIVE) == 0) {
    QuotaNode* parent = node->parent;  // never null: the root is never closed
    const uint64_t unused = give_back(node);
    const bool empty = (node->flags & FLAG_EXISTS) == 0;
    node->lock.release();
    if (unused == 0 && !empty) {
      return;  // nothing to pass on
    }
    parent->lock.acquire();
    free_node_page(t, take_back(parent, node, unused, empty));
    node = parent;
  }
  node->lock.release();
}

// Call with `top->lock` held and `top` closed; returns with it still held.
// Closes every node beneath `top`. Coming back up, each node gives its unused
// allowance to its parent once everything beneath it has done the same, so
// that all of it ends up with `top`, and nodes left holding nothing are freed
// on the way.
//
// The walk keeps its place with the tree's own links rather than recursing
// (a syscall body runs on a fixed slice of the caller's stack). It holds the
// lock of every node from `top` down to where it is, taking each parent's
// before its child's, so nothing on that path can be unlinked or freed
// meanwhile: `parent` and `next_sibling` are always safe to follow.
void close_subtree(Tree& t, QuotaNode* top) {
  QuotaNode* node = top;
  QuotaNode* next = top->first_child;
  for (;;) {
    if (next != nullptr) {
      QuotaNode* child = next;
      child->lock.acquire();
      if ((child->flags & FLAG_LIVE) != 0) {
        // Close it and go down into it.
        child->flags &= ~FLAG_LIVE;
        node = child;
        next = child->first_child;
      } else {
        // Closed already, as is everything beneath it, and none of it holds
        // unused allowance. Skip it.
        next = child->next_sibling;
        child->lock.release();
      }
      continue;
    }

    // Everything beneath `node` is closed and has given back. Give `node`
    // back to its parent, then go on to the parent's next child.
    if (node == top) {
      return;
    }
    QuotaNode* parent = node->parent;
    next = node->next_sibling;  // read now: take_back() may unlink `node`
    const uint64_t unused = give_back(node);
    const bool empty = (node->flags & FLAG_EXISTS) == 0;
    Capability page = take_back(parent, node, unused, empty);
    node->lock.release();
    free_node_page(t, page);
    node = parent;
  }
}

}  // namespace

void init(Tree& t, OType type) {
  t.type = type;
  t.root_taken = false;
  t.live_nodes = 0;
  init_node(&t.root, 0, FLAG_ROOT);
  t.root.flags = 0;
}

// Accepts a closed node that has not been freed yet, so that refunds of what
// is still outstanding keep reaching it. Whether a closed node is acceptable
// is up to each operation, which checks FLAG_LIVE under the node's lock.
QuotaNode* unseal(Tree& t, Capability handle) {
  return sealing::open_live<QuotaNode>(t.type, handle, FLAG_EXISTS);
}

Capability create_root(Tree& t, uint64_t total_bytes) {
  if (t.root_taken) {
    return nullptr;
  }

  init_node(&t.root, total_bytes, FLAG_ROOT);
  // The root is static but unseals like any other node: its handle
  // leads back to it through `self_page`.
  t.root.self_page = capability_set_bounds(
      reinterpret_cast<Capability>(&t.root), sizeof(QuotaNode));

  Capability handle = seal_node(t, &t.root, perms::DataRw);
  if (!capability_is_valid(handle)) {
    t.root.flags = 0;
    return nullptr;
  }

  t.root_taken = true;
  t.live_nodes = 1;
  return handle;
}

Capability derive(Tree& t, Capability parent_handle, uint64_t amount_bytes,
                  uint64_t perms_mask, Status* out_status) {
  QuotaNode* parent = unseal(t, parent_handle);
  if (parent == nullptr) {
    return fail_with(out_status, Status::InvalidCapability);
  }
  if (!capability_has_perms(parent_handle, perms::Store)) {
    return fail_with(out_status, Status::InsufficientPermission);
  }

  // What the child costs its parent: an allocation like any other, of the
  // child's allowance plus the page the child lives in.
  const uint64_t total_cost = amount_bytes + QUOTA_NODE_COST;
  if (total_cost < amount_bytes) {
    return fail_with(out_status, Status::OutOfQuota);
  }

  // Refused here first, cheaply, so a request that cannot succeed never makes
  // the kernel buy a page.
  {
    Locked hold(parent->lock);
    if ((parent->flags & FLAG_LIVE) == 0) {
      return fail_with(out_status, Status::InvalidCapability);
    }
    // The node's own page is billed to the parent alongside the child's
    // budget, so a subtree can hold at most limit_bytes / QUOTA_NODE_COST
    // descendants.
    if (total_cost > parent->available()) {
      return fail_with(out_status, Status::OutOfQuota);
    }
  }

  // Bought with the lock released: vm::alloc_pages runs a revocation sweep
  // when memory is short, and the sweep refunds into this tree.
  Capability page = vm::alloc_pages(QUOTA_NODE_PAGES);
  if (!capability_is_valid(page)) {
    return fail_with(out_status, Status::NoMemory);
  }

  // Everything is checked again: the parent may have been charged, closed or
  // even freed meanwhile, and a sweep may have cleared the tag on `parent`.
  parent = unseal(t, parent_handle);
  if (parent == nullptr) {
    vm::free_pages(page);
    return fail_with(out_status, Status::InvalidCapability);
  }
  Locked hold(parent->lock);
  if ((parent->flags & FLAG_LIVE) == 0) {
    vm::free_pages(page);
    return fail_with(out_status, Status::InvalidCapability);
  }
  if (total_cost > parent->available()) {
    vm::free_pages(page);
    return fail_with(out_status, Status::OutOfQuota);
  }

  QuotaNode* child = reinterpret_cast<QuotaNode*>(page);
  init_node(child, amount_bytes, 0);
  child->self_page = page;
  child->parent = parent;

  // Link at the head of the parent's child list (O(1)).
  child->next_sibling = parent->first_child;
  if (parent->first_child != nullptr) {
    parent->first_child->prev_sibling = child;
  }
  parent->first_child = child;
  parent->allocated_bytes += total_cost;

  Capability handle =
      seal_node(t, child, perms_mask & (perms::Load | perms::Store));
  if (!capability_is_valid(handle)) {
    // Unwind rather than leak the page and the debit.
    parent->first_child = child->next_sibling;
    if (parent->first_child != nullptr) {
      parent->first_child->prev_sibling = nullptr;
    }
    parent->allocated_bytes -= total_cost;
    vm::free_pages(page);
    return fail_with(out_status, Status::InvalidCapability);
  }

  __atomic_fetch_add(&t.live_nodes, 1, __ATOMIC_RELAXED);
  if (out_status != nullptr) {
    *out_status = Status::Ok;
  }
  return handle;
}

Status destroy(Tree& t, Capability handle) {
  QuotaNode* node = unseal(t, handle);
  if (node == nullptr) {
    return Status::InvalidCapability;
  }
  if (!capability_has_perms(handle, perms::Store)) {
    return Status::InsufficientPermission;
  }

  node->lock.acquire();
  if ((node->flags & FLAG_LIVE) == 0 || node->parent == nullptr) {
    // Closed already, or the root: static, with nobody to refund.
    node->lock.release();
    return Status::InvalidCapability;
  }

  // Close it and everything beneath it, which gathers every unused byte in
  // the subtree into `node`, then give all of that to the parent. A node with
  // nothing outstanding is freed on the spot; the rest are freed by refund()
  // when their last allocation comes back.
  node->flags &= ~FLAG_LIVE;
  close_subtree(t, node);
  refund_unused(t, node);  // releases node->lock
  return Status::Ok;
}

Status charge(Tree& t, Capability handle, uint64_t bytes) {
  if (!sealing::is_sealed_as(t.type, handle)) {
    return Status::InvalidCapability;
  }
  if (!capability_has_perms(handle, perms::Load)) {
    return Status::InsufficientPermission;
  }
  QuotaNode* node = unseal(t, handle);
  if (node == nullptr) {
    return Status::InvalidCapability;
  }
  Locked hold(node->lock);
  if ((node->flags & FLAG_LIVE) == 0) {
    return Status::InvalidCapability;
  }
  if (bytes > node->available()) {
    return Status::OutOfQuota;
  }
  node->allocated_bytes += bytes;
  return Status::Ok;
}

Status refund(Tree& t, Capability handle, uint64_t bytes) {
  if (!sealing::is_sealed_as(t.type, handle)) {
    return Status::InvalidCapability;
  }
  if (!capability_has_perms(handle, perms::Load)) {
    return Status::InsufficientPermission;
  }
  // A closed node still takes refunds of what is outstanding, so FLAG_LIVE is
  // not checked here.
  QuotaNode* node = unseal(t, handle);
  if (node == nullptr) {
    return Status::InvalidCapability;
  }
  node->lock.acquire();
  if ((node->flags & FLAG_EXISTS) == 0) {
    node->lock.release();
    return Status::InvalidCapability;
  }
  if (bytes > node->allocated_bytes) {
    node->lock.release();
    return Status::OutOfQuota;
  }
  node->allocated_bytes -= bytes;

  // A live node keeps what came back. A closed one never holds unused
  // allowance: it refunds it to its parent at once, and a closed parent does
  // the same, up to the first live ancestor.
  refund_unused(t, node);  // releases node->lock
  return Status::Ok;
}

bool query(Tree& t, Capability handle, QuotaNode* out_copy) {
  QuotaNode* node = unseal(t, handle);
  if (node == nullptr) {
    return false;
  }
  Locked hold(node->lock);
  if ((node->flags & FLAG_LIVE) == 0) {
    return false;
  }
  if (out_copy != nullptr) {
    *out_copy = *node;
  }
  return true;
}

// --- VM tree ---------------------------------------------------------------

Tree& vm_tree() { return s_vm_tree; }

void init() {
  init(s_vm_tree, OType::QuotaVm);
}

  // SIGNETOS_QUOTA_SELFTEST

}  // namespace signetos::quota
