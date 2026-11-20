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

// malloc.hpp - `malloc`, `calloc`, `realloc` and `free` for a program
//
// A program holds no allocator, so these get every block from the `heap`
// service (abi.hpp, "Heap service"). C code can then run unchanged.
//
// USING IT
//   Add MALLOC_MANIFEST(X) to a manifest that names the switcher
//   (SYS_COMP_INVOKE), and SIGNETOS_MALLOC() after it, at namespace scope in
//   `signetos::user`, outside any unnamed namespace. The VM size it asks for
//   must also cover the heap and its revocation marks (vm.hpp).
//
// THE HEAP
//   The first `malloc` makes it with `heap.create`, paid by the program's VM
//   quota; `use_heap` uses a heap made elsewhere instead. Call `shutdown`
//   before the program ends: nothing else frees the heap (DESIGN.md 5.7.1).
//   Its arena is refunded only after a sweep, which `malloc` does not wait
//   for, so a `malloc` soon after `shutdown` usually fails.
//
// WHERE THE HANDLE IS
//   The service frees by handle, but `free` gets a pointer. So each block is
//   asked for 16 bytes more and its sealed handle is stored in the first 16.
//   `malloc` returns the block's own capability with the address moved past
//   the handle and the bounds unchanged, so `free` finds the handle at the
//   base. No table is needed, and a block passed to another compartment can
//   be freed there. A holder can overwrite the handle, but then cannot free
//   the block (`heap.free` refuses it; `bad_frees` counts it). It cannot
//   forge a handle to free anything else: only the service makes them.
//
// WAITING FOR A SWEEP
//   A freed block stays in quarantine, charged to its quota, until a sweep
//   covers it, so the service may refuse what the next sweep would allow.
//   `malloc` then sleeps in `heap.wait` (a program cannot sleep by itself)
//   and retries. It returns null if the request fails with nothing left in
//   quarantine, or after WAIT_CALLS waits (each up to HEAP_WAIT_MAX_US).
//
// WHAT IT DOES NOT DO
//   One thread only: the heap is made on first use without a lock, and
//   `State::slot` is shared. (The service locks the heap, so compartments
//   can share one.) `realloc` never shrinks: a smaller size returns `ptr`.

#pragma once

#include <stdlib.h>

#include "runtime.hpp"

// --- What a program's manifest needs (user/manifest.hpp) ----------------------
#define MALLOC_MANIFEST(X)                            \
  M_QUOTA_VM(X, MALLOC_VM_QUOTA)                      \
  M_SERVICE(X, MALLOC_HEAP_CREATE, "heap.create")     \
  M_SERVICE(X, MALLOC_HEAP_ALLOC, "heap.alloc")       \
  M_SERVICE(X, MALLOC_HEAP_FREE, "heap.free")         \
  M_SERVICE(X, MALLOC_HEAP_DESTROY, "heap.destroy")   \
  M_SERVICE(X, MALLOC_HEAP_WAIT, "heap.wait")

// The size of the heap the first `malloc` makes.
#if !defined(SIGNETOS_MALLOC_HEAP_BYTES)
#define SIGNETOS_MALLOC_HEAP_BYTES (64 * 1024)
#endif

namespace signetos::user::malloc_shim {

// What the manifest lines above were granted.
struct Grants {
  Capability invoke;    // the switcher
  Capability vm_quota;  // pays for the heap
  Capability create;    // heap.*
  Capability alloc;
  Capability free;
  Capability destroy;
  Capability wait;
};

// Defined by SIGNETOS_MALLOC(), from the program's capability table.
void grants(Grants* out);

// In front of what `malloc` returns: the block's handle.
constexpr size_t HEADER = sizeof(Capability);
// The largest request: with the header it must not wrap.
constexpr size_t MAX_REQUEST = ~size_t{0} - 2 * HEADER;
// Calls of `heap.wait` one `malloc` makes before it gives up.
constexpr uint64_t WAIT_CALLS = 1200;

struct State {
  Grants g = {};
  Capability quota = nullptr;  // the heap: its root quota, or the one given
  // Where the service stores a block's capability (`heap.alloc`'s `out`).
  alignas(sizeof(Capability)) Capability slot = nullptr;
  size_t heap_bytes = SIGNETOS_MALLOC_HEAP_BYTES;
  bool have_grants = false;
  bool owned = false;       // the heap was made here: `shutdown` destroys it
  uint64_t waits = 0;       // calls of `heap.wait`
  uint64_t refused = 0;     // requests that returned null
  uint64_t bad_frees = 0;   // frees the shim or the service refused
  int64_t last_status = 0;  // why the last refused request was refused
};
inline constinit State s_state = {};

inline State& state() {
  State& s = s_state;
  if (!s.have_grants) {
    grants(&s.g);
    s.have_grants = true;
  }
  return s;
}

// Before the first `malloc`: the size of the heap it will make.
inline void set_heap_bytes(size_t bytes) { s_state.heap_bytes = bytes; }

// Before the first `malloc`: allocate from the heap `quota` names (it needs
// Permit_Load). Whoever made that heap destroys it; `shutdown` does not.
inline void use_heap(Capability quota) {
  s_state.quota = quota;
  s_state.owned = false;
}

// The heap's quota handle: null before the first `malloc`.
inline Capability heap() { return s_state.quota; }
inline bool owns_heap() { return s_state.owned; }

// Calls of `heap.wait` so far, requests that returned null, and refused
// frees: a pointer that is no block's, or a handle the service refused
// (freed already, or overwritten).
inline uint64_t waits() { return s_state.waits; }
inline uint64_t refused() { return s_state.refused; }
inline uint64_t bad_frees() { return s_state.bad_frees; }
// The status the service last refused a request with (HEAP_*).
inline int64_t last_status() { return s_state.last_status; }

// True if there is a heap to allocate from, after making one if need be.
inline bool ready() {
  State& s = state();
  if (capability_is_valid(s.quota)) {
    return true;
  }
  const Capability quota =
      invoke<Capability>(s.g.invoke, s.g.create, s.g.vm_quota, s.heap_bytes);
  if (!capability_is_valid(quota)) {
    s.last_status = static_cast<int64_t>(capability_get_address(quota));
    return false;
  }
  s.quota = quota;
  s.owned = true;
  return true;
}

// Destroys the heap, if it was made here: every block of it is gone. 0, or
// the service's status.
inline int64_t shutdown() {
  State& s = state();
  int64_t status = 0;
  if (s.owned && capability_is_valid(s.quota)) {
    status = invoke<int64_t>(s.g.invoke, s.g.destroy, s.quota);
  }
  s.quota = nullptr;
  s.owned = false;
  return status;
}

// A block of `bytes` bytes and its handle, or null if refused. Waits for
// sweeps as WAITING FOR A SWEEP says.
inline Capability take(size_t bytes, Capability* handle) {
  if (!ready()) {
    return nullptr;
  }
  State& s = s_state;
  const Capability out = capability_set_bounds(
      reinterpret_cast<Capability>(&s.slot), sizeof(Capability));
  bool drained = false;  // nothing was left in quarantine at the last look
  for (uint64_t calls = 0;;) {
    s.slot = nullptr;
    const Capability made =
        invoke<Capability>(s.g.invoke, s.g.alloc, s.quota, bytes, out);
    if (capability_is_valid(made)) {
      *handle = made;
      // Read from memory: the service stored it there.
      return *reinterpret_cast<volatile Capability*>(&s.slot);
    }
    s.last_status = static_cast<int64_t>(capability_get_address(made));
    // Only these three can change after a sweep; the others are final.
    if (s.last_status != init::HEAP_OVER_QUOTA &&
        s.last_status != init::HEAP_NEEDS_SWEEP &&
        s.last_status != init::HEAP_NO_MEMORY) {
      return nullptr;
    }
    if (drained || calls >= WAIT_CALLS) {
      return nullptr;
    }
    const int64_t left = invoke<int64_t>(s.g.invoke, s.g.wait, s.quota,
                                         init::HEAP_WAIT_MAX_US);
    calls += 1;
    s.waits += 1;
    if (left < 0) {
      s.last_status = left;
      return nullptr;
    }
    drained = left == 0;  // one more try, and that is the answer
  }
}

// Waits as `malloc` does until nothing is left in quarantine, so the quotas
// charge only live blocks. Returns the bytes left there (0: none), or a status.
inline int64_t settle() {
  State& s = state();
  if (!capability_is_valid(s.quota)) {
    return 0;
  }
  int64_t left = 0;
  for (uint64_t calls = 0; calls < WAIT_CALLS; ++calls) {
    left = invoke<int64_t>(s.g.invoke, s.g.wait, s.quota,
                           init::HEAP_WAIT_MAX_US);
    s.waits += 1;
    if (left <= 0) {
      break;
    }
  }
  return left;
}

// What can be used of the block `ptr` points into, from `ptr` on.
inline size_t usable_size(const void* ptr) {
  const Capability cap = const_cast<void*>(ptr);
  return capability_get_length(cap) -
         (capability_get_address(cap) - capability_get_base(cap));
}

}  // namespace signetos::user::malloc_shim

// --- The four functions <stdlib.h> declares -----------------------------------

inline void* malloc(size_t size) {
  namespace shim = ::signetos::user::malloc_shim;
  if (size > shim::MAX_REQUEST) {
    shim::s_state.refused += 1;
    return nullptr;
  }
  ::signetos::Capability handle = nullptr;
  const ::signetos::Capability block = shim::take(size + shim::HEADER, &handle);
  if (!::signetos::capability_is_valid(block)) {
    shim::s_state.refused += 1;
    return nullptr;
  }
  // Handle first, the caller's part after it (WHERE THE HANDLE IS).
  *reinterpret_cast<::signetos::Capability*>(block) = handle;
  return reinterpret_cast<char*>(block) + shim::HEADER;
}

inline void free(void* ptr) {
  namespace shim = ::signetos::user::malloc_shim;
  using ::signetos::Capability;
  if (ptr == nullptr) {
    return;
  }
  shim::State& s = shim::state();
  const Capability cap = ptr;
  const uint64_t base = ::signetos::capability_get_base(cap);
  // Only what `malloc` returned has a handle to find: tagged, unsealed, 16
  // bytes past a 16-aligned base.
  if (!::signetos::capability_is_valid(cap) ||
      ::signetos::sealing::is_sealed(cap) || (base & (shim::HEADER - 1)) != 0 ||
      ::signetos::capability_get_address(cap) != base + shim::HEADER ||
      ::signetos::capability_get_length(cap) < shim::HEADER) {
    s.bad_frees += 1;
    return;
  }
  const Capability handle = *reinterpret_cast<const Capability*>(
      ::signetos::capability_set_address(cap, base));
  const int64_t status =
      ::signetos::user::invoke<int64_t>(s.g.invoke, s.g.free, handle);
  if (status != ::signetos::init::HEAP_OK) {
    s.last_status = status;
    s.bad_frees += 1;
  }
}

inline void* calloc(size_t nmemb, size_t size) {
  size_t bytes = 0;
  if (__builtin_mul_overflow(nmemb, size, &bytes)) {
    ::signetos::user::malloc_shim::s_state.refused += 1;
    return nullptr;
  }
  return malloc(bytes);  // a block arrives zeroed (abi.hpp, AN ALLOCATION)
}

inline void* realloc(void* ptr, size_t size) {
  namespace shim = ::signetos::user::malloc_shim;
  using ::signetos::Capability;
  if (ptr == nullptr) {
    return malloc(size);
  }
  if (size == 0) {
    free(ptr);
    return nullptr;
  }
  const size_t have = shim::usable_size(ptr);
  if (size <= have) {
    return ptr;
  }
  void* fresh = malloc(size);
  if (fresh == nullptr) {
    return nullptr;  // the old block is as it was
  }
  // Copy a capability at a time: one copied as bytes or integers loses its
  // tag. `have` is a multiple of 16 and both blocks are 16-byte aligned.
  // Volatile keeps the loop a loop: no `memcpy` is linked into a compartment.
  const auto* from = reinterpret_cast<const volatile Capability*>(ptr);
  auto* to = reinterpret_cast<Capability*>(fresh);
  for (size_t i = 0; i < have / sizeof(Capability); ++i) {
    to[i] = from[i];
  }
  free(ptr);
  return fresh;
}

// Defines `malloc_shim::grants` for this program. Use once, as USING IT says.
#define SIGNETOS_MALLOC()                                                   \
  void malloc_shim::grants(malloc_shim::Grants* out) {                      \
    const ::signetos::Capability* rw = ::signetos::user::rw_table();        \
    out->invoke = rw[SLOT_SYS_COMP_INVOKE];                                 \
    out->vm_quota = rw[SLOT_MALLOC_VM_QUOTA];                               \
    out->create = rw[SLOT_MALLOC_HEAP_CREATE];                              \
    out->alloc = rw[SLOT_MALLOC_HEAP_ALLOC];                                \
    out->free = rw[SLOT_MALLOC_HEAP_FREE];                                  \
    out->destroy = rw[SLOT_MALLOC_HEAP_DESTROY];                            \
    out->wait = rw[SLOT_MALLOC_HEAP_WAIT];                                  \
  }
