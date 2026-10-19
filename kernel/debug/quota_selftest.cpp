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
 * quota_selftest.cpp - Boot-time self-test of the quota tree (QUOTA_SELFTEST=1)
 *
 * Runs once at boot, before `init`, against a scratch subtree of `root`, and
 * panics on the first failed check. Every node it makes is reclaimed by the
 * end, so the tree is left as it was found. It uses only the public quota
 * API (quota.hpp).
 *
 * Costs below count pages: a node's page is one, and `derive(x, n)` takes
 * n + 1 from x. A node page that is freed stays charged to the parent until
 * a sweep reclaims it (quota.hpp, FREED MEMORY STAYS CHARGED), so checks of
 * what has come back `settle` first.
 */

#include <signetos/compartment.hpp>
#include <signetos/debug/report.hpp>
#include <signetos/hw/uart.hpp>
#include <signetos/quota.hpp>
#include <signetos/revoke.hpp>
#include <signetos/syscall.hpp>
#include <signetos/vm.hpp>

namespace signetos::quota {
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
    debug::panic("quota self-test");
  }
}

// Sweeps until nothing is left in quarantine. A sweep's refunds can empty a
// closed node, whose page then waits for the next sweep, so it may take a
// few.
void settle() {
  for (int i = 0; i < 8; ++i) {
    revoke::sweep();
    if (vm::quarantined_pages() == 0) {
      return;
    }
  }
  check(false, "quarantine drains");
}

void run(Capability root) {
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
    check(available_of(p) == base - PAGE, "the freed node page stays charged");
    settle();
    check(available_of(p) == base, "the sweep refunds it");
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
    settle();
    check(available_of(p) == base, "last refund returns the rest");
    check(live_nodes() == nodes + 1, "last refund reclaims the node");
  }

  // 3. Destroying a node closes its subtree and returns every unused byte.
  {
    Capability q = derive(p, 8 * PAGE, RW);
    Capability q2 = derive(q, 2 * PAGE, RW);
    check(charge(q, PAGE) == Status::Ok, "charge parent");
    check(destroy(q) == Status::Ok, "destroy parent with a child");
    // q keeps its one page and its node; q2 held nothing and is gone.
    settle();
    check(available_of(p) == base - 2 * PAGE, "subtree returns all unused");
    check(charge(q2, PAGE) != Status::Ok, "child of a destroyed node is closed");
    check(destroy(q2) != Status::Ok, "closed child cannot be destroyed again");
    check(live_nodes() == nodes + 2, "empty child reclaimed, parent remains");
    check(refund(q, PAGE) == Status::Ok, "refund parent");
    settle();
    check(available_of(p) == base, "finished parent returns the rest");
    check(live_nodes() == nodes + 1, "both reclaimed");
  }

  // 4. A closed descendant with an allocation outstanding keeps its closed
  //    ancestors alive; its last refund reclaims them all.
  {
    Capability q = derive(p, 4 * PAGE, RW);
    Capability r = derive(q, PAGE, RW);
    check(charge(r, PAGE) == Status::Ok, "charge grandchild");
    check(destroy(q) == Status::Ok, "destroy middle");
    // Out: r's page, r's node, q's node. q's other two pages are back.
    check(available_of(p) == base - 3 * PAGE, "only what is held stays out");
    check(destroy(r) != Status::Ok, "grandchild already closed");
    check(live_nodes() == nodes + 3, "both remain");
    check(refund(r, PAGE) == Status::Ok, "refund grandchild");
    settle();
    check(available_of(p) == base, "cascade returns everything");
    check(live_nodes() == nodes + 1, "cascade reclaims both");
  }

  // 5. Unused allowance at every depth returns to the live parent in one call.
  {
    Capability a = derive(p, 16 * PAGE, RW);
    Capability b = derive(a, 8 * PAGE, RW);
    Capability c = derive(b, 4 * PAGE, RW);
    check(charge(b, PAGE) == Status::Ok, "charge middle");
    check(destroy(a) == Status::Ok, "destroy top");
    // c held nothing and is gone. Out: b's page, b's node, a's node.
    settle();
    check(available_of(p) == base - 3 * PAGE, "every level's unused is back");
    check(charge(c, PAGE) != Status::Ok, "grandchild gone");
    check(charge(b, PAGE) != Status::Ok, "child closed");
    check(live_nodes() == nodes + 3, "a and b remain");
    check(refund(b, PAGE) == Status::Ok, "refund middle");
    settle();
    check(available_of(p) == base, "all reclaimed");
    check(live_nodes() == nodes + 1, "no nodes left");
  }

  // 6. A refund into a closed node reaches the live parent at once, through
  //    a closed node in between.
  {
    Capability q = derive(p, 8 * PAGE, RW);
    Capability r = derive(q, 4 * PAGE, RW);
    check(charge(r, 2 * PAGE) == Status::Ok, "charge grandchild twice");
    check(destroy(q) == Status::Ok, "destroy middle");
    // Out: r's two pages, r's node, q's node.
    check(available_of(p) == base - 4 * PAGE, "held pages stay out");
    check(refund(r, PAGE) == Status::Ok, "refund one page");
    check(available_of(p) == base - 3 * PAGE,
          "refunded page passes through the closed middle at once");
    check(live_nodes() == nodes + 3, "both still exist");
    check(refund(r, PAGE) == Status::Ok, "refund the other page");
    settle();
    check(available_of(p) == base, "all reclaimed");
    check(live_nodes() == nodes + 1, "both reclaimed");
  }

  // 7. Destroy steps over a child that is closed already, and a later refund
  //    into that child still reaches the live parent.
  {
    Capability q = derive(p, 8 * PAGE, RW);
    Capability r = derive(q, 4 * PAGE, RW);
    check(charge(r, PAGE) == Status::Ok, "charge child");
    check(destroy(r) == Status::Ok, "destroy child first");
    // Out of q: r's page and r's node.
    check(available_of(q) == 6 * PAGE, "child's unused is back in its parent");
    check(destroy(q) == Status::Ok, "destroy parent over a closed child");
    // Out: r's page, r's node, q's node.
    check(available_of(p) == base - 3 * PAGE, "only what is held stays out");
    check(live_nodes() == nodes + 3, "both remain");
    check(refund(r, PAGE) == Status::Ok, "refund child");
    settle();
    check(available_of(p) == base, "cascade returns everything");
    check(live_nodes() == nodes + 1, "cascade reclaims both");
  }

  // 8. Destroy walks a wide and deep subtree, freeing nodes as it goes and
  //    keeping the one still in use.
  {
    Capability q = derive(p, 16 * PAGE, RW);
    Capability a = derive(q, 4 * PAGE, RW);
    Capability a1 = derive(a, PAGE, RW);
    Capability b = derive(q, 2 * PAGE, RW);
    Capability c = derive(q, 2 * PAGE, RW);
    check(charge(b, PAGE) == Status::Ok, "charge middle child");
    check(destroy(q) == Status::Ok, "destroy wide subtree");
    // a, a1 and c held nothing and are gone. Out: b's page, b's node, q's node.
    settle();
    check(available_of(p) == base - 3 * PAGE, "every unused byte is back");
    check(charge(a, PAGE) != Status::Ok, "empty child gone");
    check(charge(a1, PAGE) != Status::Ok, "empty grandchild gone");
    check(charge(c, PAGE) != Status::Ok, "empty sibling gone");
    check(destroy(b) != Status::Ok, "busy child closed");
    check(live_nodes() == nodes + 3, "q and b remain");
    check(refund(b, PAGE) == Status::Ok, "refund middle child");
    settle();
    check(available_of(p) == base, "all reclaimed");
    check(live_nodes() == nodes + 1, "no nodes left");
  }

  check(destroy(root) != Status::Ok, "the root cannot be destroyed");
  check(destroy(p) == Status::Ok, "destroy scratch parent");
  check(live_nodes() == nodes, "no nodes leaked");

  // 9. The scratch parent's page is quarantined, and the root pays for it
  //    until a revocation sweep reclaims it. The tree works as before
  //    afterwards.
  {
    check(vm::quarantined_pages() > 0, "freed node pages await the sweep");
    check(available_of(root) == root_before - PAGE,
          "and stay charged until it");
    revoke::sweep();
    check(vm::quarantined_pages() == 0, "sweep reclaims the freed pages");
    check(available_of(root) == root_before, "the sweep refunds them");
    Capability q = derive(root, 4 * PAGE, RW);
    check(capability_is_valid(q), "derive after the sweep");
    check(charge(q, PAGE) == Status::Ok, "charge after the sweep");
    check(destroy(q) == Status::Ok, "destroy after the sweep");
    check(refund(q, PAGE) == Status::Ok, "refund after the sweep");
    settle();
    check(available_of(root) == root_before, "root restored after the sweep");
    check(live_nodes() == nodes, "no nodes leaked after the sweep");
  }

  // 10. Revoking part of an allocation (revoke.hpp, THE BASE RULE): every
  //     capability based inside the range dies at the sweep, wherever it is
  //     kept; the owner's capabilities based at the allocation, and the
  //     kernel's record of it, survive, so the allocation can still be freed.
  //     The marks go with the sweep, so the range can be handed out again.
  {
    Capability q = derive(root, 64 * PAGE, RW);
    Capability comp = compartment::create(q, nullptr);
    check(capability_is_valid(comp), "create a scratch compartment");
    Capability other = compartment::allocate(comp, q, PAGE, 0);
    const uint64_t before_arena = available_of(q);
    Capability arena = compartment::allocate(comp, q, 4 * PAGE, FLAG_REVOCABLE);
    check(capability_is_valid(arena) && capability_is_valid(other),
          "allocate an arena and another page");
    const uint64_t a = capability_get_base(arena);
    check(a % vm::SHADOW_SPAN == 0, "a revocable allocation starts on a span");
    check(available_of(q) == before_arena - 5 * PAGE,
          "and is charged one page of shadow");
    auto carve = [](Capability from, uint64_t at, uint64_t len) {
      return capability_set_bounds(capability_set_address(from, at), len);
    };
    Capability object = carve(arena, a + 256, 64);
    Capability inner = carve(object, a + 272, 16);  // derived from the object
    Capability head = carve(arena, a, 256);         // based at the allocation
    Capability span = carve(arena, a + PAGE - 64, 128);  // across two pages
    Capability tail = carve(span, a + PAGE + 32, 16);    // in the second

    // Kept in memory the sweep scans, outside the ranges: in the first page,
    // which is scanned before the second, and in another allocation.
    Capability* slots = reinterpret_cast<Capability*>(arena);
    Capability* elsewhere = reinterpret_cast<Capability*>(other);
    slots[64] = object;
    slots[65] = inner;
    slots[66] = arena;
    slots[67] = head;
    slots[68] = tail;
    elsewhere[0] = object;
    elsewhere[1] = span;

    uint64_t epoch = 0;
    check(revoke::revoke(comp, arena) != Status::Ok,
          "the whole allocation cannot be revoked");
    check(revoke::revoke(comp, head) != Status::Ok,
          "a range with the allocation's first byte cannot be revoked");
    check(revoke::revoke(comp, carve(other, capability_get_base(other) + 64,
                                     16)) == Status::NotInRange,
          "nothing in an allocation that is not revocable can be revoked");
    check(revoke::revoke(comp, carve(arena, a + 264, 16)) ==
                  Status::BadAlignment &&
              revoke::revoke(comp, carve(arena, a + 256, 24)) ==
                  Status::BadAlignment,
          "a range must start and end on a multiple of 16 bytes");
    check(revoke::revoke(comp, object, &epoch) == Status::Ok,
          "revoke an object inside the allocation");
    check(revoke::revoke(comp, span) == Status::Ok,
          "revoke an object across two pages");
    check(revoke::completed_epoch() < epoch, "not swept yet");
    revoke::sweep();
    check(revoke::completed_epoch() >= epoch, "the sweep completes the epoch");
    check(!capability_is_valid(slots[64]), "the object is revoked");
    check(!capability_is_valid(slots[65]), "what was derived from it too");
    check(capability_is_valid(slots[66]), "the owner keeps the allocation");
    check(capability_is_valid(slots[67]), "and what is based at its start");
    check(!capability_is_valid(slots[68]),
          "a capability scanned before its range's page is revoked");
    check(!capability_is_valid(elsewhere[0]) &&
              !capability_is_valid(elsewhere[1]),
          "copies kept in another allocation are revoked");

    // The object handed out again survives the next sweep that scans. It is
    // derived from the copy in memory: the compiler may still hold the
    // revoked `object` and reuse it for the same expression on `arena`.
    slots[64] = carve(slots[66], a + 256, 64);
    check(compartment::deallocate(comp, q, other) == Status::Ok,
          "free the other page, so that the next sweep scans");
    revoke::sweep();
    check(capability_is_valid(slots[64]), "the sweep cleared the marks");

    check(compartment::deallocate(comp, q, arena) == Status::Ok,
          "the kernel's record survives: the allocation can be freed");
    check(compartment::destroy(comp) == Status::Ok, "destroy the compartment");
    check(destroy(q) == Status::Ok, "destroy its quota");
    settle();
    check(available_of(root) == root_before, "root restored after revoking");
    check(live_nodes() == nodes, "no nodes leaked after revoking");
  }

  // 11. Sweeps come at most once per SWEEP_INTERVAL_US (revoke.hpp, WHEN A
  //     SWEEP RUNS). One has just ended, so asking for the next epoch is told
  //     to wait while there is something to scan, and completes at once
  //     while there is nothing.
  {
    check(revoke::request() == 0,
          "nothing to scan: the epoch completes at once");
    check(destroy(derive(root, PAGE, RW)) == Status::Ok,
          "free a node page, to have something to scan");
    check(revoke::request() > 0,
          "something to scan, too soon after the last sweep: wait");
    settle();
  }
  uart::print("[quota]    self-test passed\n");
}

}  // namespace

}  // namespace signetos::quota

namespace signetos::debug {

void quota_self_test(Capability root) { quota::run(root); }

}  // namespace signetos::debug
