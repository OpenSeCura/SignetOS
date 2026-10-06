/*
 * Copyright 2026 Google LLC (Cherified Team)
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
 * See quota.hpp for the node lifetime and authentication model.
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
  node->child_count = 0;
  node->limit_bytes = limit_bytes;
  node->allocated_bytes = 0;
  node->delegated_bytes = 0;
  node->active_threads = 0;
  node->flags = flags | FLAG_LIVE;
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

}  // namespace

void init(Tree& t, OType type) {
  t.type = type;
  t.root_taken = false;
  t.live_nodes = 0;
  init_node(&t.root, 0, FLAG_ROOT);
  t.root.flags = 0;
}

QuotaNode* unseal(Tree& t, Capability handle) {
  return sealing::open_live<QuotaNode>(t.type, handle, FLAG_LIVE);
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

  const uint64_t total_cost = amount_bytes + QUOTA_NODE_COST;
  if (total_cost < amount_bytes) {
    return fail_with(out_status, Status::OutOfQuota);
  }

  Locked hold(parent->lock);
  if ((parent->flags & FLAG_LIVE) == 0) {
    return fail_with(out_status, Status::InvalidCapability);
  }

  // The node's own page is billed to the parent alongside the child's budget,
  // so a subtree can hold at most limit_bytes / QUOTA_NODE_COST descendants.
  if (total_cost > parent->available()) {
    return fail_with(out_status, Status::OutOfQuota);
  }

  Capability page = vm::alloc_pages(QUOTA_NODE_PAGES);
  if (!capability_is_valid(page)) {
    return fail_with(out_status, Status::NoMemory);
  }

  QuotaNode* child = reinterpret_cast<QuotaNode*>(page);
  init_node(child, amount_bytes, 0);
  child->self_page = page;
  child->parent = parent_handle;

  // Link at the head of the parent's child list (O(1)).
  child->next_sibling = parent->first_child;
  if (parent->first_child != nullptr) {
    parent->first_child->prev_sibling = child;
  }
  parent->first_child = child;
  parent->child_count += 1;
  parent->delegated_bytes += total_cost;

  Capability handle =
      seal_node(t, child, perms_mask & (perms::Load | perms::Store));
  if (!capability_is_valid(handle)) {
    // Unwind rather than leak the page and the debit.
    parent->first_child = child->next_sibling;
    if (parent->first_child != nullptr) {
      parent->first_child->prev_sibling = nullptr;
    }
    parent->child_count -= 1;
    parent->delegated_bytes -= total_cost;
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

  QuotaNode* parent = unseal(t, node->parent);
  if (parent == nullptr) {
    Locked hold_node(node->lock);
    if ((node->flags & FLAG_LIVE) == 0) {
      return Status::InvalidCapability;
    }
    if (node->child_count != 0) {
      return Status::HasChildren;
    }
    if (node->allocated_bytes != 0 || node->active_threads != 0) {
      return Status::StillAllocated;
    }
    // The root is static and has nobody to refund.
    return Status::InvalidCapability;
  }

  Capability page = nullptr;
  {
    // Lock parent before child to prevent deadlock with derive().
    Locked hold_parent(parent->lock);
    Locked hold_node(node->lock);
    if ((node->flags & FLAG_LIVE) == 0) {
      return Status::InvalidCapability;
    }
    if (node->child_count != 0) {
      return Status::HasChildren;
    }
    if (node->allocated_bytes != 0 || node->active_threads != 0) {
      return Status::StillAllocated;
    }

    // Unlink in O(1).
    if (node->prev_sibling != nullptr) {
      node->prev_sibling->next_sibling = node->next_sibling;
    } else {
      parent->first_child = node->next_sibling;
    }
    if (node->next_sibling != nullptr) {
      node->next_sibling->prev_sibling = node->prev_sibling;
    }
    parent->child_count -= 1;
    parent->delegated_bytes -= (node->limit_bytes + QUOTA_NODE_COST);

    // Release the node. The page is quarantined, not unmapped: handles held by
    // other compartments keep their tags until the revocation sweep runs, and
    // must keep reaching valid memory until then. What refuses them is the
    // cleared FLAG_LIVE and self_page below, which unseal() checks.
    page = node->self_page;
    node->self_page = nullptr;
    node->parent = nullptr;
    node->first_child = nullptr;
    node->next_sibling = nullptr;
    node->prev_sibling = nullptr;
    node->limit_bytes = 0;
    node->flags = 0;
  }

  vm::free_pages(page);
  __atomic_fetch_sub(&t.live_nodes, 1, __ATOMIC_RELAXED);
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
  QuotaNode* node = unseal(t, handle);
  if (node == nullptr) {
    return Status::InvalidCapability;
  }
  Locked hold(node->lock);
  if ((node->flags & FLAG_LIVE) == 0) {
    return Status::InvalidCapability;
  }
  if (bytes > node->allocated_bytes) {
    return Status::OutOfQuota;
  }
  node->allocated_bytes -= bytes;
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

}  // namespace signetos::quota
