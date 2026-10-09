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

// Call with `node->lock` held. True if the node is closed and holds nothing.
// FLAG_EXISTS is then cleared under the lock, which makes the caller the only
// one that will ever see true for this node: it must free_node() it once the
// lock is dropped. Nothing else can reach it after that: every entry point
// requires FLAG_LIVE or FLAG_EXISTS, and it funds nothing that could release
// into it.
bool claim_if_finished(QuotaNode* node) {
  if ((node->flags & (FLAG_LIVE | FLAG_EXISTS)) != FLAG_EXISTS ||
      node->allocated_bytes != 0 || node->child_count != 0 ||
      node->active_threads != 0) {
    return false;
  }
  node->flags &= ~FLAG_EXISTS;
  return true;
}

// Frees a node claimed by claim_if_finished(): unlinks it, gives the parent
// back limit + QUOTA_NODE_COST and quarantines its page. If that leaves the
// parent closed and holding nothing, the parent goes the same way, and so on
// up. Called with no lock held and holds one parent lock at a time, so it
// cannot invert destroy()'s parent-before-child order.
void free_node(Tree& t, QuotaNode* node) {
  while (node != nullptr) {
    // Still reachable: a node with a child linked to it is never finished.
    QuotaNode* parent = unseal(t, node->parent);
    if (parent == nullptr) {
      return;  // only the root has no parent, and the root is never closed
    }

    QuotaNode* next = nullptr;
    Capability page = nullptr;
    {
      Locked hold(parent->lock);
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
      if (claim_if_finished(parent)) {
        next = parent;
      }

      // The page is quarantined, not unmapped: handles held by other
      // compartments keep reaching it until the revocation sweep, and are
      // refused by the cleared flags and self_page, which unseal() checks.
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
    node = next;
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

// Accepts a closed node that has not been freed yet, so that refunds keep
// reaching it while it drains. Whether a closed node is acceptable is up to
// each operation, which checks FLAG_LIVE under the node's lock.
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

  // Bought with no quota lock held: vm::alloc_pages runs a revocation sweep
  // when memory is short, and the sweep refunds into quota nodes -- possibly
  // this one, whose lock is not recursive.
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

  // A closed parent still counts: children outlive their parent's destroy.
  QuotaNode* parent = unseal(t, node->parent);
  if (parent == nullptr) {
    // The root is static and has nobody to refund.
    return Status::InvalidCapability;
  }

  bool finished = false;
  {
    // Lock parent before child to prevent deadlock with derive().
    Locked hold_parent(parent->lock);
    Locked hold_node(node->lock);
    if ((node->flags & FLAG_LIVE) == 0) {
      return Status::InvalidCapability;
    }

    // Close it. From here on no handle can charge, derive or destroy through
    // it, but whatever it funded carries on and still refunds into it.
    node->flags &= ~FLAG_LIVE;

    // Give back now what it is not using. What it is using comes back when it
    // is reclaimed, as limit + QUOTA_NODE_COST.
    const uint64_t unused = node->available();
    node->limit_bytes -= unused;
    parent->delegated_bytes -= unused;

    finished = claim_if_finished(node);
  }

  if (finished) {
    free_node(t, node);
  }
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
  // A closed node still takes refunds: that is how it drains, so FLAG_LIVE is
  // not checked here.
  QuotaNode* node = unseal(t, handle);
  if (node == nullptr) {
    return Status::InvalidCapability;
  }
  bool finished = false;
  {
    Locked hold(node->lock);
    if ((node->flags & FLAG_EXISTS) == 0) {
      return Status::InvalidCapability;
    }
    if (bytes > node->allocated_bytes) {
      return Status::OutOfQuota;
    }
    node->allocated_bytes -= bytes;
    finished = claim_if_finished(node);
  }
  if (finished) {
    free_node(t, node);
  }
  return Status::Ok;
}

void release_thread(Tree& t, Capability handle, uint64_t bytes) {
  QuotaNode* node = unseal(t, handle);
  if (node == nullptr) {
    return;
  }
  bool finished = false;
  {
    Locked hold(node->lock);
    if ((node->flags & FLAG_EXISTS) == 0) {
      return;
    }
    node->allocated_bytes -=
        (bytes < node->allocated_bytes) ? bytes : node->allocated_bytes;
    if (node->active_threads > 0) {
      node->active_threads -= 1;
    }
    finished = claim_if_finished(node);
  }
  if (finished) {
    free_node(t, node);
  }
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

#ifdef SIGNETOS_QUOTA_SELFTEST
// --- Self-test (QUOTA_SELFTEST=1) -------------------------------------------
//
// Runs once at boot, before `init`, against a scratch subtree of `root`, and
// panics on the first failed check. Every node it makes is reclaimed by the
// end, so the tree is left as it was found.

namespace {

constexpr uint64_t PAGE = vm::PAGE_SIZE;
constexpr uint64_t RW = perms::Load | perms::Store;

uint64_t available_of(Capability handle) {
  QuotaNode copy;
  return query(handle, &copy) ? copy.available() : ~0ULL;
}

void check(bool ok, const char* what) {
  if (!ok) {
    uart::print("[quota]    self-test FAILED: ");
    uart::print(what);
    uart::print("\n");
    uart::panic("quota self-test");
  }
}

}  // namespace

void self_test(Capability root) {
  const size_t nodes = live_nodes();
  const uint64_t root_before = available_of(root);
  Capability p = derive(root, 64 * PAGE, RW);
  check(capability_is_valid(p), "derive scratch parent");
  const uint64_t base = available_of(p);

  // 1. Destroying an empty node reclaims it at once.
  {
    Capability q = derive(p, 4 * PAGE, RW);
    check(available_of(p) == base - 5 * PAGE, "derive debits limit + node");
    check(destroy(q) == Status::Ok, "destroy empty");
    check(available_of(p) == base, "empty destroy refunds everything");
    check(live_nodes() == nodes + 1, "empty destroy reclaims the node");
    check(charge(q, PAGE) != Status::Ok, "stale handle cannot charge");
    check(destroy(q) != Status::Ok, "stale handle cannot destroy");
  }

  // 2. Destroying a node with an allocation closes it and returns the unused
  //    part at once; the last refund reclaims it.
  {
    Capability q = derive(p, 4 * PAGE, RW);
    check(charge(q, PAGE) == Status::Ok, "charge");
    check(destroy(q) == Status::Ok, "destroy with an allocation");
    check(available_of(p) == base - 2 * PAGE, "unused comes back at once");
    check(charge(q, PAGE) != Status::Ok, "closed node refuses charges");
    check(!capability_is_valid(derive(q, PAGE, RW)),
          "closed node refuses derive");
    check(live_nodes() == nodes + 2, "closed node still exists");
    check(refund(q, PAGE) == Status::Ok, "closed node takes refunds");
    check(available_of(p) == base, "last refund returns the rest");
    check(live_nodes() == nodes + 1, "last refund reclaims the node");
  }

  // 3. A child outlives its parent's destroy and keeps working.
  {
    Capability q = derive(p, 8 * PAGE, RW);
    Capability q2 = derive(q, 2 * PAGE, RW);
    check(charge(q, PAGE) == Status::Ok, "charge parent");
    check(destroy(q) == Status::Ok, "destroy parent with a child");
    // q keeps 1 page allocated and 3 delegated to q2; the other 4 come back.
    check(available_of(p) == base - 5 * PAGE, "parent returns only unused");
    check(charge(q2, PAGE) == Status::Ok, "child of closed node can charge");
    check(refund(q2, PAGE) == Status::Ok, "child of closed node can refund");
    check(destroy(q2) == Status::Ok, "child of closed node can be destroyed");
    check(available_of(p) == base - 5 * PAGE, "nothing more until q drains");
    check(refund(q, PAGE) == Status::Ok, "refund parent");
    check(available_of(p) == base, "finished parent returns the rest");
    check(live_nodes() == nodes + 1, "both reclaimed");
  }

  // 4. Reclaim cascades up through closed ancestors.
  {
    Capability q = derive(p, 4 * PAGE, RW);
    Capability r = derive(q, PAGE, RW);
    check(charge(r, PAGE) == Status::Ok, "charge grandchild");
    check(destroy(q) == Status::Ok, "destroy middle");
    check(destroy(r) == Status::Ok, "destroy grandchild");
    check(live_nodes() == nodes + 3, "both still draining");
    check(refund(r, PAGE) == Status::Ok, "refund grandchild");
    check(available_of(p) == base, "cascade returns everything");
    check(live_nodes() == nodes + 1, "cascade reclaims both");
  }

  check(destroy(p) == Status::Ok, "destroy scratch parent");
  check(available_of(root) == root_before, "root restored");
  check(live_nodes() == nodes, "no nodes leaked");
  uart::print("[quota]    self-test passed\n");
}
#endif  // SIGNETOS_QUOTA_SELFTEST

}  // namespace signetos::quota
