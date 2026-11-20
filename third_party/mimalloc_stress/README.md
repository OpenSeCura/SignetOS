# mimalloc stress test (vendored)

The allocator stress test of mimalloc, which the mimalloc-bench suite runs as
its `mstress` benchmark, for SignetOS programs that allocate through the heap
service.

- Upstream: https://github.com/microsoft/mimalloc
- Commit: 8c532c32c3c96e5ba1f2283e032f69ead8add00f (tag `v2.1.7`, 2024-05-21)
- Licence: MIT, see [LICENSE](LICENSE)

| File here | Upstream path | State |
| --- | --- | --- |
| `test-stress.cpp` | `test/test-stress.c` | adapted, see below |
| `LICENSE` | `LICENSE` | as upstream |

The file is named `.cpp` to follow SignetOS naming, and is built as C++, which
upstream allows for. It is not compiled on its own: `external/apps/mstress.cpp`
includes it, and holds everything that is SignetOS's own (the manifest, the
entry point, the C library functions the test calls, and its "threads").

To see the whole difference from upstream, check out mimalloc at the commit
above and diff the test against it:

    diff -u mimalloc/test/test-stress.c third_party/mimalloc_stress/test-stress.cpp

The section below lists every change.

## What was changed, and why

The test is upstream's: what it allocates, in what order, with what random
numbers, and how it checks a block when it frees it.

- **`<stdbool.h>`** is included only when the file is built as C. SignetOS
  has no such header, and C++ needs none.
- **`DATA_STEP`**, a macro, is how many entries the `data` array of `stress`
  grows by at a time. Upstream has the number, 100000, in place, and that is
  still the default. A pointer is a 16-byte capability here, so one step is
  about 1.5 MiB, more than a small heap holds; `mstress.cpp` sets a smaller
  one.
- **`TEST_STRESS_NO_OS_THREADS`**, when defined, leaves out both
  implementations of `run_os_threads` and `atomic_exchange_ptr` (Windows
  threads; pthreads with `<atomic>` or `<stdatomic.h>`). A SignetOS program
  has one thread and none of those headers, so `mstress.cpp` defines the two
  functions itself: a compartment is one worker (or runs the workers in
  turn), and the exchange is one atomic instruction on a capability.
- **`TEST_STRESS_EXTERNAL_TRANSFER`**, when defined, leaves out the file's
  `static volatile void* transfer[TRANSFERS]` so that `mstress.cpp` can
  point `transfer` either at an array of its own or at a block in a shared
  heap that several compartments exchange pointers through.

## What is set from outside, without a change to the file

`mstress.cpp` includes the file with these in force:

- `USE_STD_MALLOC`, upstream's own switch: the test calls `calloc`,
  `realloc` and `free`, which `user/malloc.hpp` provides.
- `main` renamed (`#define main test_stress_main`), so that SignetOS's entry
  point can call it with an `argv` of its own. THREADS, SCALE and ITER are
  still read from `argv` by upstream's code.
- `assert` redefined to print the expression and end the program with a
  failure status. `include/libc/assert.h` only traps.
- `UINTPTR_MAX` defined (`include/libc/stdint.h` has none). Without it the
  test would silently take its 32-bit random number generator.
- The warning `-Wcheri-provenance` switched off around the include. A
  `uintptr_t` is a capability here, as in any CHERI C, so every item the
  test writes into a block is 16 bytes, and where it XORs two of them the
  compiler asks which one the result takes its bounds from. They are plain
  numbers and have none.
- `NULL` redefined as `nullptr`: `include/libc/stddef.h` has C's
  `((void*)0)`, which does not convert to the test's `void**` in C++.
- The defaults of THREADS, SCALE and ITER and `allow_large_objects`, which
  are variables of the file, are assigned before `main` is called: upstream's
  defaults are for large machines. As upstream, large objects are allowed
  again when SCALE is over 100.
