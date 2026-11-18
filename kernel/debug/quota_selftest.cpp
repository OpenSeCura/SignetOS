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

// How a compartment holds a handle: in a page of the pool, where a sweep
// finds it. This test is kernel code, and the kernel's own stack and
// registers are no part of a sweep (vm.hpp, CHECKED PAGES), so a handle it
// keeps across one, to show that it is refused afterwards, is kept here and
// read back.
volatile Capability* s_kept = nullptr;

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
  const Capability kept = vm::alloc_pages(1);
  check(capability_is_valid(kept), "a page to keep handles in");
  s_kept = reinterpret_cast<volatile Capability*>(kept);
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
    s_kept[0] = q;
    settle();
    q = s_kept[0];
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
    s_kept[0] = q2;
    settle();
    q2 = s_kept[0];
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
    s_kept[0] = c;
    settle();
    c = s_kept[0];
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
    s_kept[0] = a;
    s_kept[1] = a1;
    s_kept[2] = c;
    settle();
    a = s_kept[0];
    a1 = s_kept[1];
    c = s_kept[2];
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
    Capability comp = compartment::create(q, nullptr, 0);
    check(capability_is_valid(comp), "create a scratch compartment");
    Capability other = compartment::allocate(comp, q, PAGE, 0);
    const uint64_t before_arena = available_of(q);
    Capability arena = compartment::allocate(comp, q, 4 * PAGE, FLAG_REVOCABLE);
    check(capability_is_valid(arena) && capability_is_valid(other),
          "allocate an arena and another page");
    const uint64_t a = capability_get_base(arena);
    check(a % vm::BITMAP_SPAN == 0, "a revocable allocation starts on a span");
    check(available_of(q) == before_arena - 6 * PAGE,
          "and is charged a page of each bitmap");
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
    // The owner may, and nobody else: another compartment holding a
    // capability to the same memory, and a handle of its own, may not.
    Capability stranger = compartment::create(q, nullptr, 0);
    check(capability_is_valid(stranger), "create a second compartment");
    check(revoke::revoke(stranger, object) == Status::NotInRange,
          "a compartment that does not own the memory cannot revoke it");
    check(compartment::destroy(stranger) == Status::Ok,
          "destroy the second compartment");
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

  // 11. A sweep is started, not run (revoke.hpp, A SWEEP). With nothing to
  //     revoke it is complete at once. With something, starting it makes
  //     every page stale: a page the kernel checks (KERNEL LOADS) has lost
  //     what was freed before the start and nothing else, the epoch
  //     completes once the sweeper has been through the rest, and what was
  //     freed meanwhile waits for the next sweep. Every load from the pool
  //     here follows a check: this is kernel code, which may not fault.
  {
    uint64_t before = revoke::completed_epoch();
    check(revoke::start() == before + 1 &&
              revoke::completed_epoch() == before + 1,
          "nothing to revoke: the sweep is complete at once");

    Capability q = derive(root, 16 * PAGE, RW);
    Capability comp = compartment::create(q, nullptr, 0);
    Capability holder = compartment::allocate(comp, q, PAGE, 0);
    Capability target = compartment::allocate(comp, q, PAGE, 0);
    Capability later = compartment::allocate(comp, q, PAGE, 0);
    check(capability_is_valid(holder) && capability_is_valid(target) &&
              capability_is_valid(later),
          "allocate a holder and two pages for it to hold");
    auto* held = reinterpret_cast<volatile Capability*>(holder);
    const uint64_t holder_at = capability_get_base(holder);
    held[0] = target;
    held[1] = later;
    check(compartment::deallocate(comp, q, target) == Status::Ok,
          "free the first before the sweep");

    before = revoke::completed_epoch();
    const uint64_t epoch = revoke::start();
    check(epoch == before + 1 && revoke::completed_epoch() == before,
          "something to revoke: the sweep is started, not complete");
    check(revoke::start() == epoch + 1 && revoke::query() == before,
          "starting again while it runs does nothing");
    revoke::check(holder_at, PAGE);
    check(!capability_is_valid(held[0]),
          "a checked page has lost what was freed before the sweep");
    check(capability_is_valid(held[1]), "and nothing else");
    check(compartment::deallocate(comp, q, later) == Status::Ok,
          "free the second while the sweep runs");
    while (revoke::step(revoke::STEP_MAX) == revoke::STEP_MORE) {
    }
    check(revoke::completed_epoch() == epoch, "the sweeper completes it");
    check(vm::quarantined_pages() == 1,
          "what was freed while it ran waits for the next sweep");
    revoke::check(holder_at, PAGE);
    check(capability_is_valid(held[1]),
          "and a page checked before that still holds it");
    revoke::sweep();
    check(vm::quarantined_pages() == 0, "which reclaims it");
    check(!capability_is_valid(held[1]), "and revokes it");

    check(compartment::destroy(comp) == Status::Ok, "destroy the compartment");
    check(destroy(q) == Status::Ok, "destroy its quota");
    settle();
    check(available_of(root) == root_before, "root restored after the sweeps");
    check(live_nodes() == nodes, "no nodes leaked after the sweeps");
  }

  // 12. Revoking while a sweep runs (revoke.hpp, TWO BITMAPS). It is not
  //     refused, and the range belongs to the next sweep. A page checked
  //     before the mark keeps its capability to the range until that sweep;
  //     a page checked after it has lost it already. The sweep that was
  //     running takes its own marks with it and leaves the new one.
  {
    Capability q = derive(root, 64 * PAGE, RW);
    Capability comp = compartment::create(q, nullptr, 0);
    Capability early = compartment::allocate(comp, q, PAGE, 0);
    Capability late = compartment::allocate(comp, q, PAGE, 0);
    Capability arena = compartment::allocate(comp, q, 4 * PAGE, FLAG_REVOCABLE);
    check(capability_is_valid(early) && capability_is_valid(late) &&
              capability_is_valid(arena),
          "allocate an arena and two pages to hold capabilities to it");
    const uint64_t a = capability_get_base(arena);
    auto carve = [](Capability from, uint64_t at, uint64_t len) {
      return capability_set_bounds(capability_set_address(from, at), len);
    };
    // Two pages, checked by hand: one before the second mark, one after it.
    auto* in_early = reinterpret_cast<volatile Capability*>(early);
    auto* in_late = reinterpret_cast<volatile Capability*>(late);
    const uint64_t early_at = capability_get_base(early);
    const uint64_t late_at = capability_get_base(late);
    const Capability first = carve(arena, a + 256, 64);
    const Capability second = carve(arena, a + 512, 64);
    in_early[0] = first;
    in_early[1] = second;
    in_early[2] = arena;
    in_late[0] = second;

    uint64_t first_epoch = 0;
    uint64_t second_epoch = 0;
    check(revoke::revoke(comp, first, &first_epoch) == Status::Ok,
          "revoke one object before the sweep");
    const uint64_t epoch = revoke::start();
    check(epoch == first_epoch && revoke::completed_epoch() < epoch,
          "the sweep that starts is the one the object waits for");
    revoke::check(early_at, PAGE);
    check(!capability_is_valid(in_early[0]) && capability_is_valid(in_early[1]),
          "a checked page has lost the first object and not the second");
    check(revoke::revoke(comp, second, &second_epoch) == Status::Ok &&
              second_epoch == epoch + 1,
          "revoking while the sweep runs is not refused, and waits for the "
          "next");
    revoke::check(late_at, PAGE);
    check(!capability_is_valid(in_late[0]),
          "a page checked after that has lost the second object already");
    while (revoke::step(revoke::STEP_MAX) == revoke::STEP_MORE) {
    }
    check(revoke::completed_epoch() == epoch, "the sweeper completes the sweep");
    check(capability_is_valid(in_early[1]),
          "the page checked before the mark still holds the second object");

    // The first object handed out again, from the copy of the arena in
    // memory (as in 10), and the next sweep.
    in_early[0] = carve(in_early[2], a + 256, 64);
    revoke::sweep();
    check(revoke::completed_epoch() >= second_epoch,
          "the next sweep completes the second object's epoch");
    check(!capability_is_valid(in_early[1]), "and revokes it there too");
    check(capability_is_valid(in_early[0]),
          "the first sweep took its own marks with it");

    check(compartment::destroy(comp) == Status::Ok, "destroy the compartment");
    check(destroy(q) == Status::Ok, "destroy its quota");
    settle();
    check(available_of(root) == root_before,
          "root restored after revoking during a sweep");
    check(live_nodes() == nodes, "no nodes leaked after revoking during one");
  }

  // 13. A compartment made from an image (compartment.hpp, LOADING ITSELF):
  //     the image waits in the loader's slot, and the handle its creator
  //     keeps can destroy it and change nothing in it, while the
  //     compartment's own handle (slot 0) can.
  {
    // The loader is not run here, and the kernel does not look at the
    // image, so any readable capability will do.
    alignas(16) static const uint8_t image_bytes[16] = {};
    const Capability image = capability_and_perms(
        reinterpret_cast<Capability>(const_cast<uint8_t*>(image_bytes)),
        perms::Load);
    Capability q = derive(root, 64 * PAGE, RW);
    Capability loader = nullptr;
    Capability comp =
        compartment::create_from_image(q, nullptr, image, 0, &loader);
    check(capability_is_valid(comp) && capability_is_valid(loader),
          "create a compartment from an image");
    const Capability* table =
        reinterpret_cast<const Capability*>(compartment::table_writable(comp));
    check(capability_is_valid(table[compartment::SLOT_LOADER_IMAGE]),
          "the image waits in the loader's slot");
    Status st = Status::Ok;
    check(!capability_is_valid(compartment::allocate(comp, q, PAGE, 0, &st)) &&
              st == Status::InvalidCapability,
          "the creator's handle cannot allocate");
    const Capability own = table[compartment::SLOT_SELF];
    Capability arena = compartment::allocate(own, q, 4 * PAGE, FLAG_REVOCABLE);
    check(capability_is_valid(arena), "the compartment's own handle can");
    check(compartment::deallocate(comp, q, arena) == Status::InvalidCapability,
          "the creator's handle cannot free");
    check(!capability_is_valid(compartment::cow(comp, q, arena, PAGE, &st)) &&
              st == Status::InvalidCapability,
          "the creator's handle cannot copy memory in");
    check(!capability_is_valid(
              sentry::create(comp, arena, perms::CodeRx, &st)) &&
              st == Status::InvalidCapability,
          "the creator's handle cannot add an entry point");
    check(compartment::install_fault_handler(comp, arena) ==
              Status::InvalidCapability,
          "the creator's handle cannot install a fault handler");
    Capability inside = capability_set_bounds(
        capability_set_address(arena, capability_get_base(arena) + 256), 64);
    check(revoke::revoke(comp, inside) == Status::InvalidCapability,
          "the creator's handle cannot revoke");
    check(compartment::destroy(comp) == Status::Ok,
          "the creator's handle can destroy");
    check(destroy(q) == Status::Ok, "destroy its quota");
    settle();
    check(available_of(root) == root_before, "root restored after the image");
    check(live_nodes() == nodes, "no nodes leaked after the image");
  }
  s_kept = nullptr;
  vm::free_pages(kept);
  settle();
  uart::print("[quota]    self-test passed\n");
}

}  // namespace

}  // namespace signetos::quota

namespace signetos::debug {

void quota_self_test(Capability root) { quota::run(root); }

}  // namespace signetos::debug
