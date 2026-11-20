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
// heap.hpp - Heaps inside a compartment
//
// A `Heap` hands out blocks of an arena the compartment already holds. A
// compartment can have any number of heaps, each on its own arena:
//
//   heap::setup(gates)    once per compartment: the revocation calls and,
//                         optionally, the scheduler's lock entries
//   Heap h;               a `constinit` global, or a member of one
//   h.init(arena)         once: the arena becomes the heap
//   h.allocate(size)      a block of at least `size` bytes, or null
//   h.free(block)         takes it back
//   h.reclaim()           puts memory whose sweep is over back in use
//
// The allocator is the CHERIoT RTOS's (third_party/cheriot_allocator, a
// dlmalloc descendant); this file is its SignetOS interface. A heap's state
// is all in its arena and its `Heap` object; the gates and the revoker
// (`core::revoker`, which makes the kernel calls) are per compartment.
//
// WHAT A BLOCK IS
//   A capability bounded exactly to the block. Its base is its address and a
//   multiple of 16. Its length is the request rounded up to a multiple of 16
//   (for a large request, first to a length a capability can bound exactly),
//   or 16 more where the remainder was too small to keep. The memory is zero.
//   The allocator's 16-byte header in front of the block is out of bounds.
//
// A FREED BLOCK IS REVOKED BEFORE IT IS REUSED
//   The arena must be FLAG_REVOCABLE memory of the compartment (syscall.hpp).
//   `free` marks the block with `sys_revoke` and keeps it in QUARANTINE until
//   a sweep has cleared the tag of every capability to it (revoke.hpp).
//   SignetOS has no load barrier, so until then those capabilities still
//   work, for reads and writes. The heap therefore keeps nothing in a
//   quarantined block (the quarantine lists run through the chunk headers),
//   and zeroes it when it leaves quarantine, not when it is freed.
//
//   Nothing here waits for a sweep: `free` asks for one when quarantine is
//   large against free memory, `allocate` when it finds no room. `allocate`
//   and `free` each move a few swept chunks out of quarantine, `reclaim` all.
//
// WHOSE BLOCK
//   `free` refuses a capability outside its heap's arena, another heap's
//   block included, and changes nothing.
//
// LOCKING
//   Every operation holds the heap's lock (runtime.hpp, `lock`): one
//   compare-and-swap to take it and one to release it when uncontended. A
//   thread that finds it taken waits if `setup` was given the scheduler's
//   lock entries, and is otherwise refused (`Why::Busy`), as is a thread
//   already inside the heap (from its fault handler, say).
//
//   With the lock held nothing waits for a sweep, and the only calls out are
//   `released` (WHO PAYS) and the kernel calls: a `sys_revoke` per `free`,
//   about one `sys_revoke_query` per operation while a sweep is awaited, and
//   at most one `sys_revoke_start` per completed epoch.
//
//   If the lock's owner ended while holding it, the lists may be
//   half-updated. The next thread to wait for the lock is told so, and the
//   heap is marked UNUSABLE: every operation is refused (`Why::Unusable`,
//   `broken()`) and the arena is never touched again. Without lock entries
//   nobody waits, so the heap stays busy for good instead. An operation that
//   faults (a failed check in a SIGNETOS_HEAP_DEBUG build) is unwound with
//   the lock held: the heap refuses that thread, and others wait until it
//   has ended.
//
// WHAT THIS DOES NOT DO YET (DESIGN.md §5.7.1 has the whole design)
//   - `free` expects the chunk header right in front of the block's base,
//     so a capability to the INSIDE of a live block, with the bytes in front
//     of it forged to look like a header, would pass: nothing outside the
//     heap records where blocks start. Inside one compartment there is
//     nobody to forge one; a service must hand out sealed handles instead
//     (external/services/heap.cpp does).
//   - No quotas, except through accounts (WHO PAYS).
//
// WHO PAYS (SIGNETOS_HEAP_OWNERS; the heap service)
//   A compartment that hands out one heap's memory in several names keeps an
//   `Account` per owner. A `Heap::Session` allocates in an owner's name (a
//   number above `OWNER`, recorded in the chunk's header) and charges the
//   owner's account the chunk's size, block plus 16-byte header, or refuses
//   (`Why::OverBudget`) if the account cannot pay. A Session holds the
//   heap's lock for its lifetime, so the compartment can read and act on its
//   records in the heap as one operation.
//
//   CHARGED UNTIL SWEPT: freeing refunds nothing. The chunk keeps its owner
//   through quarantine; when it leaves, the heap calls the image's
//   `released(arena, owner, bytes)`, which refunds. That runs with the heap's
//   lock held, inside whichever operation moved the chunk, and must not call
//   into any heap.
//
// BUILDING
//   Needs `-Ithird_party/cheriot_allocator -Iuser/heap` (the Makefile adds
//   them); no global constructor. Options, defined before this file:
//   - SIGNETOS_HEAP_DEBUG: the allocator's own (slow) consistency checks. A
//     failed one prints through `signetos_heap_debug_write`, which the image
//     must then define (user/heap/heap_compat.hpp), and traps.
//   - SIGNETOS_HEAP_NO_REVOCATION: no temporal safety. `setup` takes only the
//     lock entries and is optional, arenas need not be revocable, and a freed
//     block is zeroed and reused at once while capabilities to it still work.
//   - SIGNETOS_HEAP_OWNERS: accounts and sessions (WHO PAYS); the image must
//     define `signetos::user::heap::released`. Needs revocation.
//

#include <signetos/sealing.hpp>
#include <signetos/syscall.hpp>
#include <signetos/types.hpp>

#include "runtime.hpp"

#if defined(SIGNETOS_HEAP_DEBUG)
#define DEBUG_ALLOCATOR 1
#define HEAP_RENDER 1
#endif

// Upstream code, kept as it is, gives these warnings under -Wall -Wextra.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wreorder-ctor"
#pragma clang diagnostic ignored "-Wpacked-non-pod"
#pragma clang diagnostic ignored "-Wdeprecated-copy-with-user-provided-copy"
#include <cheri.hpp>
#pragma clang diagnostic pop

#if !defined(SIGNETOS_HEAP_NO_REVOCATION)

namespace signetos::user::heap {

// The gates the heaps revoke with (syscall.hpp), handed to `setup`.
struct RevokeGates {
  Capability invoke;        // the switcher (`compartment_invoke`)
  Capability self;          // the compartment's own handle: it owns the arenas
  Capability revoke;        // `sys_revoke`
  Capability revoke_query;  // `sys_revoke_query`
  Capability revoke_start;  // `sys_revoke_start`
};

// The allocator's revoker (allocator.hpp, `Revocation`) on SignetOS's calls:
// `sys_revoke` marks a range and returns its epoch, epoch e has finished once
// `sys_revoke_query() >= e`, and `sys_revoke_start` kicks a sweep. User space
// cannot read the revocation bitmap, so there are no chunk marks. Threads in
// two heaps can use it at once, so each of its words is atomic and no two
// are relied on to agree.
class SweepRevoker {
 public:
  static constexpr bool IsAsynchronous = true;
  static constexpr bool HasChunkMarks = false;

  // Kernel calls made so far by all the compartment's heaps.
  struct Calls {
    uint64_t revoke;
    uint64_t query;
    uint64_t start;
  };

  // One capability at a time: a struct copy of this size could become a
  // call to `memcpy`, which no compartment has.
  void set_gates(const RevokeGates& g) {
    gates_.invoke = g.invoke;
    gates_.self = g.self;
    gates_.revoke = g.revoke;
    gates_.revoke_query = g.revoke_query;
    gates_.revoke_start = g.revoke_start;
  }

  // Whether `set_gates` has been called.
  bool has_gates() const { return capability_is_valid(gates_.invoke); }

  // Marks `range` so that sweep `epoch` revokes every capability based in
  // it. False if the kernel refused: the memory must never be reused.
  bool mark_set_range(::CHERI::Capability<void> range, size_t& epoch) {
    using Fn = decltype(&sys_revoke);
    count(&calls_.revoke);
    epoch = syscall::call<Fn>(gates_.invoke, gates_.revoke, gates_.self,
                              static_cast<Capability>(range.get()));
    return epoch != 0;
  }

  // Whether sweep `epoch` has completed. The completed epoch only grows, so
  // the kernel is asked only if the highest one seen says "not yet".
  bool has_revocation_finished_for_epoch(size_t epoch) {
    return completed() >= epoch || query() >= epoch;
  }

  // Asks for a sweep, at most once per completed epoch: `sys_revoke_start`
  // does nothing while a sweep runs, so asking again before that sweep
  // completes would be wasted. After it completes, the next call asks again.
  void system_bg_revoker_kick() {
    const uint64_t done = completed();
    if (load(&asked_) > done) {
      return;
    }
    using Fn = decltype(&sys_revoke_start);
    count(&calls_.start);
    syscall::call<Fn>(gates_.invoke, gates_.revoke_start);
    // `done` predates the call, so sweep `done + 1` has now been started.
    raise(&asked_, done + 1);
  }

  // `sys_revoke_query`: the completed epoch.
  uint64_t query() {
    using Fn = decltype(&sys_revoke_query);
    count(&calls_.query);
    const uint64_t done = syscall::call<Fn>(gates_.invoke, gates_.revoke_query);
    raise(&completed_, done);
    return done;
  }

  // The highest completed epoch seen so far: no call.
  uint64_t completed() const { return load(&completed_); }

  // For a caller that can only wait for quarantined memory, whose oldest
  // epoch is `eldest`: asks for a sweep and returns an epoch whose sweep is
  // under way or complete: `eldest`, or the one before it if that has not
  // been seen to complete (the caller then waits again, for `eldest`). No
  // query: the allocator has just looked for completed sweeps.
  uint64_t sweep_under_way(uint64_t eldest) {
    const uint64_t done = completed();
    if (eldest <= done) {
      return eldest;
    }
    system_bg_revoker_kick();
    return done + 1;
  }

  const Calls& calls() const { return calls_; }

  // No chunk marks (HasChunkMarks): never asked, and nothing to keep.
  bool mark_get(ptraddr_t) { return false; }
  void mark_set_one(::CHERI::Capability<void>) {}
  void mark_clear_one(ptraddr_t) {}
  void mark_clear_range(size_t, size_t) {}

 private:
  static uint64_t load(const uint64_t* word) {
    return __atomic_load_n(word, __ATOMIC_SEQ_CST);
  }
  static void count(uint64_t* counter) {
    __atomic_fetch_add(counter, 1, __ATOMIC_SEQ_CST);
  }
  // Atomically raises `*word` to `value` if it is lower; never lowers it.
  static void raise(uint64_t* word, uint64_t value) {
    uint64_t seen = load(word);
    while (seen < value &&
           !__atomic_compare_exchange_n(word, &seen, value, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
    }
  }

  RevokeGates gates_ = {};
  uint64_t completed_ = 0;  // the highest answer of `sys_revoke_query` so far
  uint64_t asked_ = 0;      // the sweep last asked for (above); 0: none yet
  Calls calls_ = {};
};

}  // namespace signetos::user::heap

#define ALLOCATOR_REVOKER ::signetos::user::heap::SweepRevoker

#endif  // !SIGNETOS_HEAP_NO_REVOCATION

#if defined(SIGNETOS_HEAP_OWNERS)
#if defined(SIGNETOS_HEAP_NO_REVOCATION)
#error "SIGNETOS_HEAP_OWNERS needs revocation: accounts are refunded when a chunk leaves quarantine"
#endif

namespace signetos::user::heap {

// Defined by the image (WHO PAYS): a chunk of `bytes` bytes, header
// included, owned by `owner` (`OWNER` too) has left quarantine. `arena` has
// the base, not the address, of that heap's arena. Called with that heap's
// lock held; must not call into a heap.
void released(Capability arena, uint32_t owner, size_t bytes);

}  // namespace signetos::user::heap

// Where the allocator calls it (alloc.hpp, `mspace_qtbin_deqn`).
#define ALLOCATOR_CHUNK_RELEASED(heap_start, owner, bytes)   \
  ::signetos::user::heap::released(                          \
      static_cast<::signetos::Capability>((heap_start).get()), (owner), \
      (bytes))

#endif  // SIGNETOS_HEAP_OWNERS

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wreorder-ctor"
#pragma clang diagnostic ignored "-Wpacked-non-pod"
#pragma clang diagnostic ignored "-Wdeprecated-copy-with-user-provided-copy"
// The allocator goes into a namespace of its own. What it includes from
// outside its directory is included first, so include guards empty its own
// #include lines and only its declarations land in the namespace. Not in
// `signetos`, where `Capability` would mean SignetOS's, not CHERI's.
#include <heap_compat.hpp>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
namespace cheriot_allocator {
#include "allocator.hpp"
}  // namespace cheriot_allocator
#pragma clang diagnostic pop

namespace signetos::user::heap {

// The allocator core, as this file names it.
namespace core = ::cheriot_allocator;

// The owner of the compartment's own blocks. 0 is the allocator's: the
// marker chunk ending the arena, and blocks the kernel would not revoke.
constexpr uint32_t OWNER = 1;

// --- Per compartment ---------------------------------------------------------

// The scheduler's lock entries (abi.hpp), handed to `setup` by a compartment
// whose heaps more than one thread uses (LOCKING).
struct LockGates {
  Capability invoke;     // the switcher (`compartment_invoke`)
  Capability lock_wait;  // `sched.lock_wait`
  Capability lock_wake;  // `sched.lock_wake`
};

// The lock entries `setup` was given; null if none.
inline constinit LockGates s_lock_gates = {};

inline bool lock_gates_ok(const LockGates& locks) {
  return sealing::is_entry(locks.invoke) &&
         sealing::is_sealed_as(OType::EntryPoint, locks.lock_wait) &&
         sealing::is_sealed_as(OType::EntryPoint, locks.lock_wake);
}

// One capability at a time, as in `SweepRevoker::set_gates`.
inline void keep_lock_gates(const LockGates& locks) {
  s_lock_gates.invoke = locks.invoke;
  s_lock_gates.lock_wait = locks.lock_wait;
  s_lock_gates.lock_wake = locks.lock_wake;
}

// Once per compartment, before any `init`. `gates.self` names the
// compartment that owns the arenas; `locks`, if given, lets threads wait for
// a heap's lock (LOCKING). False, with nothing changed, if a gate is wrong
// or this was done already.
#if !defined(SIGNETOS_HEAP_NO_REVOCATION)
inline bool setup(const RevokeGates& gates, const LockGates* locks = nullptr) {
  if (core::revoker.has_gates() || !sealing::is_entry(gates.invoke) ||
      !sealing::is_sealed_as(OType::Compartment, gates.self) ||
      !sealing::is_sealed_as(OType::EntryPoint, gates.revoke) ||
      !sealing::is_sealed_as(OType::EntryPoint, gates.revoke_query) ||
      !sealing::is_sealed_as(OType::EntryPoint, gates.revoke_start) ||
      (locks != nullptr && !lock_gates_ok(*locks))) {
    return false;
  }
  core::revoker.set_gates(gates);
  if (locks != nullptr) {
    keep_lock_gates(*locks);
  }
  return true;
}
#else
inline bool setup(const LockGates& locks) {
  if (capability_is_valid(s_lock_gates.invoke) || !lock_gates_ok(locks)) {
    return false;
  }
  keep_lock_gates(locks);
  return true;
}
#endif

// --- Per heap ----------------------------------------------------------------

// Why `allocate` returned what it did.
enum class Why : uint8_t {
  Granted,     // a block
  TooBig,      // null, for good: no heap, 0 bytes, or more than the arena holds
  Full,        // null: not enough memory is free, even counting quarantine
  NeedsSweep,  // null: quarantine holds enough, and a sweep is under way.
               // Retry once `sys_revoke_query()` reaches `Refusal::epoch`;
               // the answer may be NeedsSweep again (a later epoch) or Full.
  Busy,        // null: another thread is inside the heap and there is no
               // way to wait, or the caller is inside it already (LOCKING)
  Unusable,    // null, for good: a thread ended inside the heap (LOCKING)
  OverBudget,  // null: the account cannot pay now (WHO PAYS). It is
               // refunded for freed blocks as they leave quarantine, and a
               // sweep has been asked for if anything is in quarantine.
};
struct Refusal {
  Why why;
  uint64_t epoch;  // NeedsSweep: the epoch to wait for; otherwise 0
};

// What blocks are charged to (WHO PAYS), kept wherever the compartment
// likes; the heap service keeps them in blocks of the heap they account for.
struct Account {
  uint64_t limit;  // the most that may be charged at once
  uint64_t used;   // charged now: chunks handed out, and freed chunks that
                   // have not left quarantine
};

// Whether `cap` is tagged right now. A sweep can clear the tag of a revoked
// capability in a thread's registers and stack at any moment (revoke.hpp),
// which the compiler does not know: it may reuse an earlier answer. The
// empty asm makes it test the tag again.
__attribute__((always_inline)) inline bool tagged_now(Capability cap) {
  __asm__ volatile("" : "+C"(cap));
  return capability_is_valid(cap);
}

// One heap. All zero at first, so it can be a `constinit` global with no
// constructor. It must not move: the scheduler knows its lock word by address.
class Heap {
 public:
  constexpr Heap() = default;
  Heap(const Heap&) = delete;
  Heap& operator=(const Heap&) = delete;

  // Makes `arena` the heap: zeroed memory (as from `sys_vm_allocate`) that
  // the caller no longer touches and no other heap shares, with address equal
  // to base, base and length multiples of 16, and permission to load and
  // store data and capabilities. It must lie inside a FLAG_REVOCABLE
  // allocation of the `setup` compartment, or every `free` fails (not
  // checked here). False, with nothing changed, if `arena` is unsuitable or
  // too small, `setup` has not been called, or this is a heap already.
  bool init(Capability arena) {
#if !defined(SIGNETOS_HEAP_NO_REVOCATION)
    if (!core::revoker.has_gates()) {
      return false;
    }
#endif
    if (!capability_is_valid(arena) || sealing::is_sealed(arena) ||
        !capability_has_perms(arena, perms::DataRw) ||
        capability_get_address(arena) != capability_get_base(arena)) {
      return false;
    }
    const Scope in(*this, true);
    if (!in) {
      return false;
    }
    __atomic_store_n(&contended_, uint64_t{0}, __ATOMIC_RELAXED);
    // `mstate_init` refuses a base or a length that is not a multiple of 16,
    // and a length too small for the state and one chunk.
    state_ = core::mstate_init(::CHERI::Capability<void>{arena},
                           capability_get_length(arena));
    return state_ != nullptr;
  }

  // A block of at least `size` bytes (WHAT A BLOCK IS), or null, with the
  // reason in `*refusal` if given. Never waits for a sweep; before giving up
  // it takes out of quarantine all that completed sweeps allow.
  Capability allocate(size_t size, Refusal* refusal = nullptr) {
    const Scope in(*this);
    if (!in) {
      say(refusal, in.why_not(), 0);
      return nullptr;
    }
    return allocate_locked(size, OWNER, nullptr, refusal);
  }

 private:
  static void say(Refusal* refusal, Why why, uint64_t epoch) {
    if (refusal != nullptr) {
      refusal->why = why;
      refusal->epoch = epoch;
    }
  }

  // `allocate` with the lock held, in the name of `owner`, charged to
  // `*account` if given (WHO PAYS).
  Capability allocate_locked(size_t size, uint32_t owner, Account* account,
                             Refusal* refusal) {
    auto answer = [&](Why why, uint64_t epoch) { say(refusal, why, epoch); };
    for (;;) {
      size_t quota = ~size_t{0};  // no account: no limit
      if (account != nullptr) {
        quota = account->used < account->limit
                    ? account->limit - account->used
                    : 0;
      }
      const size_t could_pay = quota;
      const core::MState::AllocationResult result =
          state_->mspace_dispatch(size, quota, owner);
      switch (result.kind) {
        case core::MState::AllocationResult::Success:
          if (account != nullptr) {
            // `quota` went down by the chunk's size. `used` is read again:
            // the call may have refunded chunks that left quarantine.
            account->used += could_pay - quota;
          }
          answer(Why::Granted, 0);
          return result.allocation;
        case core::MState::AllocationResult::RevocationNeeded:
          // Quarantine could cover the request. While swept chunks remain in
          // it, move some out and retry; each round shortens the quarantine.
          if (state_->quarantine_dequeue()) {
            continue;
          }
#if !defined(SIGNETOS_HEAP_NO_REVOCATION)
          answer(Why::NeedsSweep,
                 core::revoker.sweep_under_way(result.waitingEpoch));
#else
          answer(Why::NeedsSweep, 0);
#endif
          return nullptr;
        case core::MState::AllocationResult::Permanent:
          answer(Why::TooBig, 0);
          return nullptr;
        case core::MState::AllocationResult::QuotaExceeded:
          if (account == nullptr) {
            answer(Why::Full, 0);  // not reached: no account, no limit
            return nullptr;
          }
          // The account may still be charged for freed chunks: move swept
          // ones out of quarantine (refunding their owners) and retry, or
          // else ask for a sweep if one could bring anything back.
          if (state_->quarantine_dequeue()) {
            continue;
          }
#if !defined(SIGNETOS_HEAP_NO_REVOCATION)
          if (state_->heapQuarantineSize > 0) {
            core::revoker.system_bg_revoker_kick();
          }
#endif
          answer(Why::OverBudget, 0);
          return nullptr;
        default:
          answer(Why::Full, 0);
          return nullptr;
      }
    }
  }

 public:
  // Takes back `block`, exactly as `allocate` returned it. Capabilities to
  // it work until sweep `*epoch` (set if given) revokes them; only then is
  // it zeroed and reused. False, with nothing changed, if:
  //   - `block` is untagged (as once freed and swept) or sealed;
  //   - its base is not a multiple of 16, or it is not inside the part of
  //     this heap's arena that holds blocks (WHOSE BLOCK);
  //   - no chunk in use is in front of its base, or its owner is not `OWNER`;
  //   - the chunk is in quarantine (freed already);
  //   - its length is not the one the chunk was handed out with;
  //   - the heap could not be entered (LOCKING), or is no heap yet.
  // Also false if the kernel refuses to revoke it (not with a correct arena,
  // see `init`); the block is then never reused.
  bool free(Capability block, uint64_t* epoch = nullptr) {
    const Scope in(*this);
    if (!in) {
      return false;
    }
    // Tested under the lock: if a copy was freed and swept while this
    // thread waited, the memory may be another block by now, but this copy
    // is then untagged.
    if (!tagged_now(block) || sealing::is_sealed(block)) {
      return false;
    }
    return free_locked(::CHERI::Capability<void>{block}, false, nullptr,
                       nullptr, epoch);
  }

 private:
  // `free` with the lock held and `mem` tagged and unsealed. With `owned`,
  // the block must have an account owner (WHO PAYS) instead of `OWNER`.
  // `*owner` and `*bytes`, if given, are set to the chunk's owner and size.
  bool free_locked(const ::CHERI::Capability<void>& mem, bool owned,
                   uint32_t* owner, size_t* bytes, uint64_t* epoch) {
    // Use the base, which the holder cannot change, not the address. Blocks
    // lie between the first chunk's header and the marker chunk at the end.
    const uint64_t base = mem.base();
    const uint64_t first =
        state_->heapStart.address() + sizeof(core::MChunkHeader);
    const uint64_t last = state_->heapStart.top() - sizeof(core::MChunkHeader);
    if ((base & core::MallocAlignMask) != 0 || base < first || base >= last ||
        mem.length() > last - base) {
      return false;
    }
    core::MChunkHeader* chunk = state_->allocation_start(base);
    if (chunk == nullptr || chunk->isQuarantined) {
      return false;
    }
    const uint32_t chunk_owner = chunk->owner();
    if (owned ? chunk_owner <= OWNER : chunk_owner != OWNER) {
      return false;
    }
    const size_t body_size = state_->chunk_body_size(*chunk);
    if (chunk->body().address() != base || body_size != mem.length()) {
      return false;
    }
    // Read before the free, which may move chunks about.
    if (owner != nullptr) {
      *owner = chunk_owner;
    }
    if (bytes != nullptr) {
      *bytes = chunk->size_get();
    }
    size_t freed_at = 0;
    if (state_->mspace_free(*chunk, body_size, &freed_at) != 0) {
      return false;
    }
    if (epoch != nullptr) {
      *epoch = freed_at;
    }
    return true;
  }

 public:
  // Moves every swept chunk out of quarantine (zeroed and merged with free
  // neighbours). Returns the bytes left in quarantine, 0 if the heap could
  // not be entered. `allocate` and `free` do a little of this on each call.
  size_t reclaim() {
    const Scope in(*this);
    if (!in) {
      return 0;
    }
    while (state_->quarantine_dequeue()) {
    }
    return state_->heapQuarantineSize;
  }

  // True once the heap is marked unusable (LOCKING).
  bool broken() const {
    return __atomic_load_n(&unusable_, __ATOMIC_SEQ_CST) != 0;
  }

  // Sleeps on this heap's lock (`sched.lock_wait`) since `init`.
  uint64_t contended() const {
    return __atomic_load_n(&contended_, __ATOMIC_RELAXED);
  }

 private:
  // How an attempt to enter the heap ended.
  enum class Entry : uint8_t {
    Ok,        // the lock is held, and the heap is as `to_init` wants it
    NoHeap,    // `init` has not been called (or, for `init`, has been)
    Busy,      // the lock was not to be had
    Unusable,  // the heap is marked unusable
  };

  // Takes the lock (LOCKING). With `to_init` the heap must not be set up yet;
  // without, it must be. The lock is held only if this returns Ok.
  Entry enter(bool to_init) {
    if (broken()) {
      return Entry::Unusable;
    }
    const int64_t status = user::lock(
        s_lock_gates.invoke, s_lock_gates.lock_wait, &lock_, &contended_);
    if (status == ::signetos::init::SCHED_OWNER_DEAD) {
      // Held, but its last owner ended inside the heap. Mark the heap before
      // letting go, so that whoever gets the lock next sees the mark.
      __atomic_store_n(&unusable_, uint64_t{1}, __ATOMIC_SEQ_CST);
      leave();
      return Entry::Unusable;
    }
    if (status != ::signetos::init::SCHED_OK) {
      return Entry::Busy;
    }
    if (broken()) {
      leave();
      return Entry::Unusable;
    }
    if ((state_ == nullptr) != to_init) {
      leave();
      return Entry::NoHeap;
    }
    return Entry::Ok;
  }

  void leave() {
    user::unlock(s_lock_gates.invoke, s_lock_gates.lock_wake, &lock_);
  }

  // Holds the lock while in scope, if it was to be had.
  struct Scope {
    Heap& heap;
    const Entry entry;
    explicit Scope(Heap& h, bool to_init = false)
        : heap(h), entry(h.enter(to_init)) {}
    ~Scope() {
      if (entry == Entry::Ok) {
        heap.leave();
      }
    }
    explicit operator bool() const { return entry == Entry::Ok; }
    // Why the heap was not entered, as `allocate` reports it.
    Why why_not() const {
      return entry == Entry::NoHeap  ? Why::TooBig
             : entry == Entry::Busy ? Why::Busy
                                    : Why::Unusable;
    }
  };

#if defined(SIGNETOS_HEAP_OWNERS)
 public:
  // Holds the heap's lock for its lifetime (WHO PAYS). Not to be held across
  // anything that can fault or wait (LOCKING).
  class Session {
   public:
    explicit Session(Heap& heap) : heap_(heap), in_(heap) {}
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    // True if the heap was entered. If not, `refused` says why (TooBig:
    // it is no heap), and nothing else here may be called.
    explicit operator bool() const { return static_cast<bool>(in_); }
    Why refused() const { return in_.why_not(); }

    // `Heap::allocate` in the name of `owner` (`OWNER` for the compartment's
    // own block), charged to `*account` if given: refused (`OverBudget`)
    // unless `limit - used` covers the chunk; `used` grows by its size.
    Capability allocate(size_t size, uint32_t owner, Account* account,
                        Refusal* refusal = nullptr) {
      return heap_.allocate_locked(size, owner, account, refusal);
    }

    // `Heap::free` for a block with an account owner; refunds nothing
    // (CHARGED UNTIL SWEPT). `*owner` and `*bytes` get the owner and the size
    // charged. The tag is tested again under the lock: if another copy was
    // freed and swept since, the memory may be another block by now, but this
    // copy is then untagged.
    bool free(Capability block, uint32_t* owner = nullptr,
              size_t* bytes = nullptr, uint64_t* epoch = nullptr) {
      if (!tagged_now(block) || sealing::is_sealed(block)) {
        return false;
      }
      return heap_.free_locked(::CHERI::Capability<void>{block}, true, owner,
                               bytes, epoch);
    }

    // `Heap::reclaim`. With `ask`, a sweep is asked for if anything is
    // left in quarantine afterwards.
    size_t reclaim(bool ask) {
      while (heap_.state_->quarantine_dequeue()) {
      }
      const size_t left = heap_.state_->heapQuarantineSize;
      if (ask && left > 0) {
        core::revoker.system_bg_revoker_kick();
      }
      return left;
    }

    // The block that starts at `address`, as `allocate` returned it.
    // `address` must be known to start a block: what lies in front of any
    // other address is not a chunk header and must not be read as one. Null
    // if the block has been freed or has no account owner.
    Capability block_at(uint64_t address) {
      core::MState* state = heap_.state_;
      const uint64_t first =
          state->heapStart.address() + sizeof(core::MChunkHeader);
      const uint64_t last =
          state->heapStart.top() - sizeof(core::MChunkHeader);
      if ((address & core::MallocAlignMask) != 0 || address < first ||
          address >= last) {
        return nullptr;
      }
      core::MChunkHeader* chunk = state->allocation_start(address);
      if (chunk == nullptr || chunk->isQuarantined ||
          chunk->owner() <= OWNER || chunk->body().address() != address) {
        return nullptr;
      }
      ::CHERI::Capability<void> block{state->heapStart};
      block.address() = address;
      block.bounds() = state->chunk_body_size(*chunk);
      return static_cast<Capability>(block.get());
    }

    // Frees every live block with an account owner that `wanted(owner)`
    // accepts, such as all blocks of an owner being closed. Walks every
    // chunk; each block freed costs what `free` costs. Returns how many.
    template <typename Wanted>
    size_t free_where(Wanted&& wanted) {
      core::MState* state = heap_.state_;
      const uint64_t start = state->heapStart.address();
      const uint64_t end = state->heapStart.top();
      size_t freed = 0;
      uint64_t at = start;
      while (at < end) {
        ::CHERI::Capability<core::MChunkHeader> header{
            state->heapStart.cast<core::MChunkHeader>()};
        header.address() = at;
        core::MChunkHeader* chunk = header;
        const size_t size = chunk->size_get();
        if (chunk->is_in_use() && !chunk->isQuarantined &&
            chunk->owner() > OWNER && wanted(chunk->owner())) {
          const size_t body = state->chunk_body_size(*chunk);
          if (state->mspace_free(*chunk, body) == 0) {
            freed += 1;
            // Quarantined chunks are not merged, so the walk can go on from
            // this one, unless the free moved it straight out of quarantine
            // (its sweep was over) and it may have merged: then start over.
            if (!chunk->isQuarantined) {
              at = start;
              continue;
            }
          }
        }
        at += size;
      }
      return freed;
    }

    size_t free_size() const { return heap_.state_->heapFreeSize; }
    size_t quarantined_size() const {
      return heap_.state_->heapQuarantineSize;
    }

    // Gives up the arena: once this Session ends, the `Heap` is as before
    // `init` and the arena is the caller's. Call nothing else here after it.
    void retire() { heap_.state_ = nullptr; }

   private:
    Heap& heap_;
    const Scope in_;
  };

  // `Session::retire` for an unusable heap (LOCKING), which nobody can
  // enter. False, with nothing changed, if the heap is not unusable. The
  // caller must not run this concurrently with itself or with `init`.
  bool retire_broken() {
    if (!broken()) {
      return false;
    }
    state_ = nullptr;
    __atomic_store_n(&unusable_, uint64_t{0}, __ATOMIC_SEQ_CST);
    return true;
  }

 private:
#endif

  // The allocator's state, at the start of the arena; null until `init`.
  core::MState* state_ = nullptr;
  // The lock (runtime.hpp): 0 when free, else the owner's tid and waiters flag.
  uint64_t lock_ = 0;
  // Sleeps on `lock_` (`sched.lock_wait`).
  uint64_t contended_ = 0;
  // Not 0: unusable (LOCKING). Cleared only by `retire_broken`.
  uint64_t unusable_ = 0;
};

}  // namespace signetos::user::heap
