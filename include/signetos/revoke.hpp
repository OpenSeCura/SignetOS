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
// revoke.hpp - SignetOS revocation
//
// A sweep clears the tag of every capability that has to die. Which ones
// those are is decided by ONE rule:
//
// THE BASE RULE
// -------------
// A capability is revoked if its BASE lies in memory that is being taken
// back: a quarantined page (`vm::free_pages`), or a range a compartment has
// marked with `revoke`. By monotonicity every capability derived from a range
// has its base inside it, so the rule catches all of them; a capability whose
// base lies outside -- the owner's capability to the allocation the range
// was carved from, or the kernel's own record of that allocation -- was not
// derived from the range and survives. (CHERIoT's revoker applies the same
// rule.)
//
// FREEING AND REVOKING
// --------------------
// Freeing a whole allocation (`sys_vm_deallocate`, compartment destroy)
// quarantines it, and quarantine is all the registration it needs. `revoke`
// is for the other case: invalidating every capability to part of an
// allocation while the owner keeps the allocation and reuses that part, as a
// heap allocator does when it frees an object. The memory is not unmapped or
// reused by the kernel; once the sweep for the returned epoch has finished
// (`completed_epoch`), the owner can safely hand it out again.
//
// WHO MAY REVOKE
// --------------
// The owner, and nobody else: the authority is the compartment handle, and
// the range must lie inside one of that compartment's own allocations
// (`compartment::owns_inside`). It must not include the allocation's first
// byte, because the base of the allocation is the base of the owner's
// capability to it, and of the kernel's record: revoking it would take the
// whole allocation from its owner and leave the kernel unable to free it. An
// allocator keeps a header (or anything) at the start of each allocation it
// carves objects from. Anyone else who needs memory revoked asks the owner.
//
// MARKING RANGES
// --------------
// `revoke` sets one bit per 16 bytes of the range in a revocation bitmap
// (vm.hpp, REVOCATION BITMAP); a sweep tests the bits under each
// capability's base and clears its own when it ends. The marks belong to
// virtual addresses, as capabilities do, so they stay right however pages
// are backed. Revoking needs no memory: a revocable allocation brings its
// bitmap pages with it, and only those can be revoked from. Both ends of a
// range must be multiples of 16 bytes, so that the bits set cover exactly
// the range. `revoke` is never refused for being made while a sweep runs.
//
// A SWEEP
// -------
// Nothing stops the machine to scan memory. A sweep has three parts.
//
//   It STARTS when a compartment says so (`start`, which is
//   `sys_revoke_start`); nothing else starts one -- no timer, no shortage of
//   memory -- and an allocation that fails, for want of quota or of frames,
//   just fails. Starting is one short step: every hart moves to a new
//   generation, which makes every page of the pool stale (vm.hpp, CHECKED
//   PAGES), and the pages the caller is running on are checked on the spot.
//   The registers the caller had are among them: the switcher saved them on
//   the thread's kernel stack on the way in, and gives them back from there.
//   The same goes for whatever every other hart is running (SEVERAL HARTS).
//
//   Every other page is CHECKED -- each revoked capability in it cleared --
//   before a capability is loaded from it. The first load from a stale page
//   traps, the page is checked, and the load runs again (`on_fault`), so a
//   compartment pays for the pages it uses, as it uses them. A thread that
//   was not running has its saved registers checked the same way before it
//   runs again, because they are in a page too. So from the moment a sweep
//   starts, no running code holds a revoked capability or can load one.
//
//   The pages nobody touches are checked by THE SWEEPER, a thread like any
//   other with a CPU budget like any other, which asks for a few pages at a
//   time (`step`, which is `sys_revoke_step`) until none is left. The sweep
//   is then complete: what was freed before it started is reclaimed, its
//   marks are cleared, and its epoch is the completed one. With pages on
//   disk it waits for those to be checked first (SWAP).
//
// Sweeps do not overlap: `start` during one does nothing. What it costs the
// rest of the system is one trap and one page check for each page a thread
// loads capabilities from, once per sweep; the sweeper's share comes out of
// its own budget.
//
// EPOCHS
// ------
// Sweeps are numbered from 1. `revoke` and `start` return the number of the
// first sweep that covers what was freed or marked before the call: the next
// one to start. That memory is safe to reuse once `completed_epoch()` has
// reached the number. Memory freed while a sweep runs is not covered by it
// (pages checked earlier may hold capabilities to it), so it waits for the
// one after.
//
// TWO BITMAPS
// -----------
// A mark made while a sweep runs must still be there when the sweep ends,
// and the marks the sweep worked from must go. So there are two bitmaps, and
// they take turns: sweep N works from bitmap N % 2 and clears it when it
// completes, and marks made from its start on go into the other one, which
// the next sweep works from. THE BASE RULE reads both: a capability to memory
// marked a moment ago is as dead as any, and is cleared wherever a check
// still finds it.
//
// KERNEL LOADS
// ------------
// The kernel never takes the trap: a fault in kernel code is a bug, and
// halts. Before it loads a capability from a page of the pool it has not
// just checked, it checks the page itself (`check`): the same check, called
// rather than trapped into. It runs on the hart's own stack and reads the
// page through the direct map, so what does the checking is never itself
// stale. Outside a sweep `check` is one test of a flag.
//
// The places, which together are every way the kernel reaches pool memory:
//
//   a thread it is about to run or tear down      its state pages (thread.cpp,
//                                                 `fresh`)
//   a system call's slice of the caller's stack   switcher.cpp, `_prepare`
//   a kernel object reached through a handle      sealing.hpp, `open_live`;
//                                                 sentry.cpp, `resolve`
//   an object reached from another                quota.cpp (a node's parent
//                                                 and children);
//                                                 compartment.cpp (range and
//                                                 entry pages, the table)
//   a compartment's memory read for a call        `vm::ResidentHold`;
//                                                 compartment.cpp, `cow`
//   a fault handler's saved context               trap.cpp, `install_context`
//
// One that is missing shows as a load page fault raised by kernel code, with
// 1 in mtval2 and the page in mtval. SWEEP_STRESS=1 (Makefile) is the build
// that looks for them.
//
// The thread that is running needs none for its own state pages: they are
// checked when a sweep starts and when it is switched to, and stay checked.
//
// SEVERAL HARTS
// -------------
// A generation is a bit of each hart's own (`mstatus.UCRG`), and the kernel's
// mappings, which the harts share, carry it too. So the harts take the step
// to a new generation together. The hart that starts a sweep first stops
// every other one (smp.hpp, THE STOP): each is interrupted where it is, in a
// compartment's code or asleep, and the trap saves the registers of the
// thread it was running on that thread's kernel stack. With all of them
// stopped the starting hart takes the step, and checks on the spot the pages
// each hart is running on: its own, and for every other hart the state pages
// of its thread, which is where those registers are. Then it lets them go.
// Each follows to the new generation before it runs anything else, and takes
// its registers back from a page that has been checked. So from that moment
// no hart holds a revoked capability, or can load one.
//
// The kernel is never stopped in the middle of anything. A hart that is
// inside a system call when it is asked finishes the call first, and what
// the call had in hand it has put down, in memory, before the step. The
// starting hart waits for that with no lock held, and a second hart that
// asks for a sweep meanwhile is told the first one's epoch.
//
// After the start each hart checks the pages it comes to. A page is checked
// by one hart, under the VM lock, through the direct map. A capability
// another hart stores into it meanwhile is not revoked (a hart stores what
// it holds) and is not lost (`scan` clears a tag only if the capability it
// looked at is still the one there). A hart whose cached translation of the
// page is older than the check traps on its next load from it, finds the
// page checked, drops the translation and runs the load again (`on_fault`).
//
// Today every thread runs on the boot hart and the others are parked
// (DESIGN.md §4.4): they are stopped and follow like any other, with no
// thread whose pages to check. SMP_SELFTEST=1 (Makefile) is the build that
// puts a thread on a second hart and starts sweeps under it.
//
// NOT BUILT: the end of a sweep. The pages it reclaims are unmapped, and
// only the hart that unmaps them drops its translations of them. No hart
// holds a capability to them by then, so nothing reaches them; but before
// their addresses are handed out again every hart has to have dropped its
// own, and nothing makes the others do it (DESIGN.md §4.4).
//
// SWAP
// ----
// A sweep checks memory, and pages on disk are not in it (vm.hpp, PAGING). If
// any of them holds capabilities, the sweep, once no page in RAM is stale,
// waits while the pager reads each such page back and clears from its bitmap
// every capability this rule picks, so that none is built again: what the
// sweep reclaimed stays Held meanwhile, its marks stay, and its epoch
// completes once the checks are done. A page that comes in from disk is
// checked on the way in, and a stale page is checked before it goes out.
//

#include <stdint.h>
#include <stddef.h>
#include <signetos/types.hpp>

namespace signetos::revoke {

// Returned when no epoch has completed yet.
constexpr uint64_t EPOCH_NONE = 0;

using Status = signetos::Status;
using signetos::status_name;

// Resets the epoch counters. Called once at boot.
void init();

// Core of `sys_revoke`. Marks `mem_cap`'s bounds `[base, top)`: every
// capability whose base lies in them is revoked (THE BASE RULE). `mem_cap`
// must be tagged and unsealed, its bounds must start and end on a multiple
// of 16 bytes (MARKING RANGES), and they must lie inside one of `comp`'s
// revocable allocations without including its first byte (WHO MAY REVOKE).
// Writes to `out_epoch` the epoch the range belongs to (EPOCHS): it has been
// swept once `completed_epoch()` reaches it.
Status revoke(Capability comp, Capability mem_cap,
              uint64_t* out_epoch = nullptr);

// Highest epoch for which the sweep has finished.
uint64_t completed_epoch();

// The epoch memory freed now belongs to (EPOCHS): the next sweep to start.
uint64_t next_epoch();

// THE BASE RULE: whether the capability with the bits of `cap`, tagged or
// not, is revoked. Every check of a page asks it of every capability in the
// page, and paging of every one it brings back from disk (SWAP). It takes no
// lock: one mark set or cleared meanwhile is one no sweep relies on yet, or
// any more.
bool is_revoked(Capability cap);

// Core of `sys_revoke_start` (A SWEEP). Starts a sweep unless one is running,
// and returns the epoch that covers everything freed or marked before the
// call (EPOCHS). With nothing to revoke the sweep is complete at once.
uint64_t start();

// Core of `sys_revoke_query`: the completed epoch. It starts nothing; a
// sweep whose last wait is over (SWAP) is completed first.
uint64_t query();

// Core of `sys_revoke_step` (A SWEEP, THE SWEEPER). Checks up to `pages`
// stale pages, one at least and STEP_MAX at most, and completes the sweep if
// that was the last of its work. Returns what is left for the caller: more
// pages (STEP_MORE), nothing for now because the sweep waits for the pager
// (STEP_WAIT; SWAP), or nothing because no sweep is running (STEP_IDLE).
constexpr size_t STEP_MAX = 64;
constexpr uint64_t STEP_IDLE = 0;
constexpr uint64_t STEP_MORE = 1;
constexpr uint64_t STEP_WAIT = 2;
uint64_t step(size_t pages);

// Kernel-internal: a whole sweep, start to finish, before it returns -- or,
// with capabilities on disk, up to the wait for those (SWAP). The boot
// self-test's way in, from host context; nothing reachable from user space
// calls it.
void sweep();

// The trap dispatcher's (A SWEEP): a load page fault at `addr` raised by
// compartment code, with STALE_LOAD in mtval2: a capability loaded from a
// stale page. True if the page has been checked, here or by another hart
// meanwhile (SEVERAL HARTS), so the load is to run again; false if the page
// is not one a check applies to.
constexpr uint64_t STALE_LOAD = 1;
bool on_fault(uint64_t addr);

// Clears the tag of every capability in `view` that THE BASE RULE picks.
// vm.cpp's, which hands it a page through the direct map (vm.hpp, CHECKED
// PAGES).
void scan(Capability view);

// KERNEL LOADS. True from the start of a sweep until no page is stale.
extern bool g_checking;
inline bool checking() {
  return __atomic_load_n(&g_checking, __ATOMIC_ACQUIRE);
}

// Checks the stale pages of `[va, va + len)`; how many there were. Not to be
// called with the VM lock held (vm_pages.hpp has that one).
size_t check_slow(uint64_t va, size_t len);

// KERNEL LOADS: called before the kernel loads a capability from
// `[va, va + len)`. Any address will do: only stale pages of the pool are
// touched.
inline void check(uint64_t va, size_t len) {
  if (checking()) {
    check_slow(va, len);
  }
}

// The same for the object at `p`; returns `p`.
template <class T>
inline T* checked(T* p) {
  check(capability_get_address(reinterpret_cast<Capability>(
            const_cast<void*>(static_cast<const void*>(p)))),
        sizeof(T));
  return p;
}

} // namespace signetos::revoke
