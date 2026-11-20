# CHERIoT allocator core (vendored)

The core of the heap allocator from the CHERIoT RTOS, adapted for SignetOS.

- Upstream: https://github.com/CHERIoT-Platform/cheriot-rtos
- Commit: e2dad05078bd25ed6f1ab993e14f332aa8c20557 (2026-11-17)
- Licence: MIT, see [LICENSE](LICENSE)

| File here | Upstream path | State |
| --- | --- | --- |
| `alloc.hpp` | `sdk/core/allocator/alloc.h` | adapted, see below |
| `ds/bits.hpp` | `sdk/include/ds/bits.h` | include lines only |
| `ds/linked_list.hpp` | `sdk/include/ds/linked_list.h` | include lines only |
| `ds/pointer.hpp` | `sdk/include/ds/pointer.h` | include lines only |
| `ds/ring_buffer.hpp` | `sdk/include/ds/ring_buffer.h` | include lines only |
| `cheri.hpp` | `sdk/include/cheri.hh` | reduced to what is used |
| `allocator.hpp`, part 1 | `sdk/core/allocator/alloc_config.h` | adapted |
| `allocator.hpp`, part 2 | `sdk/core/allocator/revoker.h` | reduced to `NoTemporalSafety`; interface changed, see below |
| `allocator.hpp`, part 3 | `sdk/core/allocator/main.cc` | `mstate_init` and `revoker` only |

The files are named `.hpp`, as SignetOS names headers.

A user of the core includes `allocator.hpp`. It holds the configuration and
the choice of revoker, then includes `alloc.hpp`, then defines `mstate_init`.
`alloc.hpp` is never included on its own.

To see the whole difference from upstream, check out cheriot-rtos at the
commit above and diff each file against its upstream path, for example

    diff -u cheriot-rtos/sdk/core/allocator/alloc.h third_party/cheriot_allocator/alloc.hpp

The section below lists every change. `allocator.hpp` and `cheri.hpp` were
taken in already reduced; each says at its top what was taken out.

`user/heap/heap_compat.hpp` holds what these files need of the C++ standard
library and of the CHERIoT SDK. SignetOS code uses the core through
`user/heap.hpp`.

## What was changed, and why

The algorithms are upstream's. The changes are what a 64-bit target with
16-byte capabilities and no CHERIoT RTOS needs.

**Include lines**

- Every header here is included under its SignetOS name. Where upstream
  includes standard-library or CHERIoT SDK headers (`<concepts>`,
  `<type_traits>`, `<cdefs.h>`, `<debug.hh>` and so on), the file includes
  SignetOS's one stand-in for them all, `<heap_compat.hpp>`. This is the
  only change to the `ds/` headers.
- `alloc.hpp` does not include its configuration and its revoker:
  `allocator.hpp` puts them in front of it.

**Sizes and alignment**

- Chunks are 16-byte aligned (`MallocAlignShift` 4, was 3): a capability is
  16 bytes here and must be stored 16-byte aligned.
- The chunk header is 16 bytes (was 8): two 32-bit compressed sizes
  (`SmallSize` is `uint32_t`, was `uint16_t`), a 29-bit owner with the
  quarantine bit and the two in-use bits, and the 32-bit quarantine link
  (see "Revocation" below). Free-list nodes grow with the address size:
  `MChunk` is 16 bytes, `TChunk` 80. The size assertions follow.
- `leftshifted_val_msb` asserts that `ssize_t` is as wide as `size_t`: it
  reads the top bit of a `size_t` through a cast to `ssize_t`.
- `MaxChunkSize` is computed in `size_t`. Upstream's `1U << 32` would be
  undefined now that `SmallSize` has 32 bits.
- `clz` and `ctz` (in `allocator.hpp`) have one overload per width.
  Upstream's take `uint32_t`; `compute_tree_index` passes a `size_t` and
  subtracts the result from the width of `size_t`, so a 32-bit count would
  put every large chunk in the wrong tree bin.
- The owner identifier is `uint32_t` (was `uint16_t`) wherever it is passed,
  to match the wider field.

**Removed, because SignetOS does not have them**

- Hazard pointers: the hazard quarantine, `hazard_*`, the epoch lock, and
  the `skipHazardCheck` parameter of `mspace_free`.
- Claims: the `claims` header field and what read it.
- The includes of CHERIoT RTOS headers, `cheriot::atomic`, and the check
  against `CHERIOTHeapMinChunkSize`.

**Removed, because no entry of SignetOS's heap service uses it**

- The mark for a block allocated as a sealed object: the `isSealedObject`
  header field, the `isSealed` parameter of `mspace_dispatch` that set it,
  and a debug check. Upstream's `heap_free_all` skips marked blocks: freeing
  one takes the sealing key as well as the quota. SignetOS has sealed
  objects, and the heap service's own handles are sealed, but the service
  has no entry that allocates a block as one, and `heap.destroy` frees every
  block of a quota. A service that kept sealed records in memory a client's
  quota pays for would need the mark back.

**Replaced, because SignetOS has no C++ standard library**

- `AllocationResult` is a small struct instead of a `std::variant`. It is
  built from the same tag types, so `mspace_dispatch` returns as before; a
  caller reads `kind` instead of asking the variant.
- The three `std::make_tuple` calls in `render()` pass their values directly
  to `invariant`.

**Revocation**

CHERIoT has a load barrier: once a freed chunk's shadow bits are painted,
no capability to it can be loaded, so upstream zeroes the chunk at once and
keeps its quarantine ring in the freed body. SignetOS has none: every
capability to a freed chunk can still load and store until the chunk's sweep
completes, and user space cannot read the kernel's marks. When chunks enter
and leave quarantine is still upstream's logic (an epoch per pending set, two
pending sets, the finished set drained a few chunks at a time, the same
heuristic for kicking the revoker). What changed:

- The revoker in use is the class named by `ALLOCATOR_REVOKER`, if the file
  that includes `allocator.hpp` defines it; `NoTemporalSafety` otherwise.
  SignetOS's revoker is in `user/heap.hpp`.
- The revoker interface (described at `namespace Revocation` in
  `allocator.hpp`). `mark_set_range` says whether it marked the range and
  gives the epoch that revokes it; `system_epoch_get` and the rounding of
  its result to an even number in `mspace_free` are gone. Epochs are
  `size_t` throughout (`NoTemporalSafety` took and returned `uint32_t`).
  A revoker says with `HasChunkMarks` whether it has shadow bits the
  allocator can read back; neither revoker here has.
- Without chunk marks, `allocation_start` takes the header to be directly
  in front of the address it is given (upstream does this for
  `NoTemporalSafety` only), and `ok_any_chunk` and the zero check in
  `mspace_malloc_success` do not ask for marks. `mark_set_one`,
  `mark_clear_one` and `mark_clear_range` are still called and do nothing.
- A quarantined chunk is known by a header bit, `isQuarantined`, taken from
  the owner field (29 bits now).
- The quarantine lists run through the chunk headers, not through
  `MChunk::ring` in the freed bodies: the header's spare 32-bit word is
  `quarantineNext`, the next chunk's offset from the start of the heap's
  memory in 16-byte units, and each pending set and the finished set is a
  `QuarantineList` (first and last chunk) in the `MState`.
  `quarantine_pending_push`, `quarantine_pending_to_finished`,
  `mspace_qtbin_deqn` and `render()` changed in how they link, not in what
  they move.
- The body is zeroed in `mspace_qtbin_deqn`, when the chunk leaves
  quarantine, and no longer in `mspace_free`. All of it, including the 16
  bytes a chunk can have beyond the bounds that were handed out.
- If the revoker cannot mark a chunk, `mspace_free` fails (`-EINVAL`, and a
  `Debug::Assert`) and leaves the chunk in use, owned by the allocator (0):
  memory that cannot be revoked is never handed out again.
- `render()` also checks that the chunks whose header says quarantined are
  exactly what the quarantine lists hold.

**Other**

- `mstate_init` no longer sets aside a hazard quarantine at the front of the
  heap.
- `mspace_free` takes a third, optional parameter, `freedEpoch`, and stores
  through it the epoch the revoker gave when it marked the chunk. One
  revoker serves every heap in an image (`user/heap.hpp`), so it cannot be
  asked afterwards for the epoch of "the last free".
- `mspace_qtbin_deqn` calls `ALLOCATOR_CHUNK_RELEASED(heapStart, ownerID,
  size)`, if that macro is defined, for each chunk it takes out of
  quarantine, before the chunk is zeroed and freed. A quarantined chunk
  keeps its `ownerID` (nothing ever cleared it), so this is where an
  owner stops being charged for a freed chunk: after the sweep, not at the
  free. `user/heap.hpp` defines the macro in a `SIGNETOS_HEAP_OWNERS` build
  (the heap service); in every other build the line is not compiled.
  Upstream refunds a quota in `heap_free`, in its compartment interface,
  which is not vendored.

## Notes for later

- `sanityCounter` in `mspace_dispatch` (how many allocations pass between
  two runs of `ok_malloc_state()`; debug builds only) is a function-local
  static, as upstream's is. With several heaps in an image it is one
  counter for all of them, and no heap's lock covers it. It only decides how
  often a debug check runs.
- The last tree bin takes every chunk of 6144 bytes or more, and its tree
  is keyed from the top bit of `size_t` down, as upstream's is. No chunk
  reaches 2^36 bytes, so with 64-bit sizes the first 28 bits are always zero
  (upstream: 13 of 32), and each costs a tree level before the tree can tell
  sizes apart. It is correct, only slower; more tree bins would fix it.

## How it is included

`user/heap.hpp` includes `allocator.hpp` inside `namespace
cheriot_allocator`, having first included, outside that namespace,
everything these files take from outside this directory. So `MState`,
`Debug`, `revoker`, the `ds` helpers and the `using namespace CHERI` are
all in that namespace, and nothing in these files was changed for it.
`cheri.hpp` is included before and outside it: `namespace CHERI` is where
upstream has it.
