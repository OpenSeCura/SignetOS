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
 * mstress.cpp - mimalloc's stress test, as a SignetOS program
 *
 * `run mstress.bin [-w WORKER] [-m KIB] [THREADS] [SCALE] [ITER]`
 *
 * The test is mimalloc's `test/test-stress.c` (mimalloc-bench's `mstress`),
 * vendored in third_party/mimalloc_stress with the changes its README.md
 * lists. This file adds the manifest, `malloc` (user/malloc.hpp), the C
 * library functions the test calls, its "threads" and the entry point.
 *
 * WORKERS: the original runs THREADS threads of `stress(tid)` at once, which
 * pass blocks to each other through `transfer`. A program has one thread, so
 * with -w this compartment runs worker WORKER (the original's `tid`) alone;
 * without -w it runs workers 0 .. THREADS-1 in turn, still passing blocks
 * through `transfer`. THREADS, SCALE and ITER go to the original's `main`.
 *
 * Exit status:
 *   0   passed.
 *   1   the test's own check failed: a freed block lost its pattern
 *       ("memory corruption ...", then `abort`) or a `calloc` block was not
 *       zero (`assert`). A line says which.
 *   2   a fault, reported as for any program. The test faults on a null
 *       `data` or `retained` array.
 *   3   an allocation was refused (the test itself skips a null block), a
 *       `free` was refused, the program's own heap did not end up empty and
 *       swept (the test frees all it allocates), or it would not be
 *       destroyed. A shared heap is checked by whoever made it.
 *   -1  bad arguments.
 */

#include "runtime.hpp"

// The heap an instance makes for itself, unless -m says otherwise.
#define SIGNETOS_MALLOC_HEAP_BYTES (1024 * 1024)
#include "malloc.hpp"

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

namespace signetos::user {
namespace {

// --- What `mstress` asks the shell for (user/manifest.hpp) -------------------
#define MSTRESS_MANIFEST(X)                           \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)   \
  M_SERVICE(X, UART_SENTRY, "uart")                   \
  M_SERVICE(X, HEAP_INFO, "heap.info")                \
  MALLOC_MANIFEST(X)

// The largest heap -m can ask for, the kernel's revocation marks for it (a
// page of each of the two bitmaps for every 512 KiB, vm.hpp), and the image.
constexpr size_t HEAP_MAX_BYTES = 4 * 1024 * 1024;
constexpr size_t MARKS_BYTES = 2 * 4096 * (HEAP_MAX_BYTES / (512 * 1024));
constexpr size_t IMAGE_BYTES = 128 * 1024;
SIGNETOS_MANIFEST(MSTRESS_MANIFEST, HEAP_MAX_BYTES + MARKS_BYTES + IMAGE_BYTES)

// The defaults here; the original's (32, 25, 50) are for large machines.
constexpr int DEFAULT_THREADS = 1;
constexpr int DEFAULT_SCALE = 4;
constexpr int DEFAULT_ITER = 50;

constexpr int64_t STATUS_PASSED = 0;
constexpr int64_t STATUS_CORRUPT = 1;  // the test's own check, or its assert
constexpr int64_t STATUS_FAULT = 2;
constexpr int64_t STATUS_HEAP = 3;     // a refused request, or the heap's end

Capability s_invoke = nullptr;
Capability s_uart = nullptr;
init::AppRequest* s_request = nullptr;
uint64_t s_ticks_per_us = 1;

// -w: the worker this compartment is; -1: all of them, in turn.
int64_t s_worker = -1;
// The program is on its way out through its fault handler.
bool s_leaving = false;
// `rand`.
uint64_t s_random = 1;

// The command line, split in place, and `argv` for the original's `main`.
char s_args[init::APP_ARGS_MAX];
char s_name[] = "mstress";
constexpr int WORDS_MAX = 8;
char* s_words[WORDS_MAX];
char* s_argv[WORDS_MAX + 1];

uint64_t now_us() {
  uint64_t ticks = 0;
  __asm__ volatile("csrr %0, time" : "=r"(ticks));
  return ticks / s_ticks_per_us;
}

void out(const char* text) { print(s_invoke, s_uart, text); }

// Every line this program prints starts with its name and its worker.
void begin(LineBuffer& line) {
  line.str("[mstress");
  if (s_worker >= 0) {
    line.put(' ');
    line.dec(static_cast<uint64_t>(s_worker));
  }
  line.str("] ");
}

// `printf`, as far as the test uses it: %d, %s, %p, %zu and %%, with a
// width for %d. One call is one line.
void emit(const char* format, va_list ap) {
  LineBuffer line;
  begin(line);
  for (const char* f = format; *f != '\0'; ++f) {
    if (*f != '%') {
      line.put(*f);
      continue;
    }
    ++f;
    size_t width = 0;
    for (; *f >= '0' && *f <= '9'; ++f) {
      width = width * 10 + static_cast<size_t>(*f - '0');
    }
    const bool is_size = *f == 'z';
    if (is_size) {
      ++f;
    }
    switch (*f) {
      case 'd': {
        const int value = va_arg(ap, int);
        const uint64_t magnitude =
            value < 0 ? 0 - static_cast<uint64_t>(value)
                      : static_cast<uint64_t>(value);
        size_t digits = value < 0 ? 2 : 1;
        for (uint64_t rest = magnitude; rest >= 10; rest /= 10) {
          digits += 1;
        }
        for (; digits < width; ++digits) {
          line.put(' ');
        }
        if (value < 0) {
          line.put('-');
        }
        line.dec(magnitude);
        break;
      }
      case 'u':
        line.dec(is_size ? va_arg(ap, size_t) : va_arg(ap, unsigned));
        break;
      case 's':
        line.str(va_arg(ap, const char*));
        break;
      case 'p':
        line.hex(capability_get_address(va_arg(ap, void*)));
        break;
      case '%':
        line.put('%');
        break;
      case '\0':
        --f;  // a lone % at the end
        break;
      default:
        line.put('%');
        line.put(*f);
        break;
    }
  }
  out(line.buf);
}

void say(const char* text) {
  LineBuffer line;
  begin(line);
  line.str(text);
  line.str("\n");
  out(line.buf);
}

// Ends the program from wherever it is, with `status`: there is no `exit`,
// so it faults on purpose, and the fault handler below unwinds the thread
// out of the compartment. The heap goes first, if it is the program's own.
[[noreturn]] void leave(int64_t status) {
  if (s_request != nullptr) {
    s_request->status = status;
  }
  malloc_shim::shutdown();
  s_leaving = true;
  __builtin_trap();
}

[[noreturn]] void assert_failed(const char* what, int line_number) {
  LineBuffer line;
  begin(line);
  line.str("FAILED: assertion `");
  line.str(what);
  line.str("` at line ");
  line.dec(static_cast<uint64_t>(line_number));
  line.str(" of the test\n");
  out(line.buf);
  leave(STATUS_CORRUPT);
}

uint64_t number(const char* text) {
  uint64_t value = 0;
  for (; *text >= '0' && *text <= '9'; ++text) {
    value = value * 10 + static_cast<uint64_t>(*text - '0');
  }
  return value;
}

bool same(const char* a, const char* b) {
  while (*a != '\0' && *a == *b) {
    ++a;
    ++b;
  }
  return *a == *b;
}

}  // namespace
}  // namespace signetos::user

// --- What the test needs of a C library ----------------------------------------
// <stdio.h> and <stdlib.h> (include/libc) declare these; nothing defines
// them for a compartment.

FILE* stderr = nullptr;  // `fprintf` below prints to the console whatever it is

int printf(const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  ::signetos::user::emit(format, ap);
  va_end(ap);
  return 0;
}

int fprintf(FILE* stream, const char* format, ...) {
  (void)stream;
  va_list ap;
  va_start(ap, format);
  ::signetos::user::emit(format, ap);
  va_end(ap);
  return 0;
}

// The test calls this when a block does not hold what was written to it.
void abort(void) {
  ::signetos::user::say("FAILED: the test called abort");
  ::signetos::user::leave(::signetos::user::STATUS_CORRUPT);
}

long strtol(const char* nptr, char** endptr, int base) {
  (void)base;  // the test asks for 10
  const char* cursor = nptr;
  long value = 0;
  for (; *cursor >= '0' && *cursor <= '9'; ++cursor) {
    value = value * 10 + (*cursor - '0');
  }
  if (endptr != nullptr) {
    *endptr = const_cast<char*>(cursor);
  }
  return value;
}

// Each worker gets a sequence of its own: the test seeds with a constant.
void srand(unsigned seed) {
  ::signetos::user::s_random =
      seed + 0x9e3779b9ULL *
                 static_cast<uint64_t>(::signetos::user::s_worker + 1);
}

int rand(void) {
  uint64_t& state = ::signetos::user::s_random;
  state = state * 6364136223846793005ULL + 1442695040888963407ULL;
  return static_cast<int>((state >> 33) & 0x7fffffff);
}

// --- The test ------------------------------------------------------------------

// A failed assertion says what failed and ends the program, where
// include/libc's only traps.
#undef assert
#define assert(expr) \
  ((expr) ? (void)0 : ::signetos::user::assert_failed(#expr, __LINE__))

// include/libc/stdint.h has no UINTPTR_MAX, and the test picks its 64-bit
// random number generator by it.
#if !defined(UINTPTR_MAX)
#define UINTPTR_MAX 0xffffffffffffffffULL
#endif

// include/libc/stddef.h has C's NULL, `((void*)0)`, which C++ will not make
// a `void**` of.
#undef NULL
#define NULL nullptr

// The test, with upstream's switch for the C library's allocator, the
// adaptations its README.md lists, and `main` renamed for `compartment_main`.
// DATA_STEP 256 (4 KiB of pointers) makes `realloc` move the `data` array,
// capabilities and all, every 256 entries. `transfer` is this compartment's
// own array unless the launcher hands in a shared block.
constexpr size_t LOCAL_TRANSFERS = 1000;
static volatile void* s_local_transfer[LOCAL_TRANSFERS];
static volatile void** transfer = s_local_transfer;

#define USE_STD_MALLOC
#define TEST_STRESS_NO_OS_THREADS
#define TEST_STRESS_EXTERNAL_TRANSFER
#define DATA_STEP 256
#define main test_stress_main
// Upstream's code, as it is. It XORs pairs of `uintptr_t` values, which are
// capabilities here, and the compiler asks which of the two the result
// should take its bounds from. Neither has any: they are plain numbers.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcheri-provenance"
#include "test-stress.cpp"
#pragma clang diagnostic pop
#undef main
static_assert(TRANSFERS == LOCAL_TRANSFERS);

// The test's threads (WORKERS, at the top of the file): `fun(tid)` for the
// worker this compartment is, or for each in turn.
static void run_os_threads(size_t nthreads, void (*fun)(intptr_t)) {
  thread_entry_fun = fun;
  (void)main_participates;  // every worker is run from here
  if (::signetos::user::s_worker >= 0) {
    thread_entry_fun(static_cast<intptr_t>(::signetos::user::s_worker));
    return;
  }
  for (size_t i = 0; i < nthreads; i++) {
    thread_entry_fun(static_cast<intptr_t>(i));
  }
}

// One instruction (amoswap.c): the slot holds a capability, and it is
// exchanged whole, tag and all.
static void* atomic_exchange_ptr(volatile void** p, void* newval) {
  return __atomic_exchange_n(const_cast<void**>(p), newval, __ATOMIC_SEQ_CST);
}

namespace signetos::user {

// A fault ends the program with STATUS_FAULT, after the usual report;
// `leave` comes through here too, with its status already set.
SIGNETOS_FAULT_HANDLER compartment_error_handler(fault::ErrorState* state) {
  if (!s_leaving) {
    s_leaving = true;
    const Capability* t = rw_table();
    report_fault_and_unwind("mstress", *state, t[SLOT_SYS_COMP_INVOKE],
                            t[SLOT_UART_SENTRY]);
    say("FAILED: fault");
    if (s_request != nullptr) {
      s_request->status = STATUS_FAULT;
    }
    malloc_shim::shutdown();
  }
  return fault::UNWIND;
}

SIGNETOS_MALLOC()

extern "C" int64_t compartment_main(Capability arg) {
  Capability* rw = rw_table();
  s_invoke = rw[SLOT_SYS_COMP_INVOKE];
  s_uart = rw[SLOT_UART_SENTRY];
  if (!sealing::is_sealed_as(OType::EntryPoint, s_uart)) {
    return -1;
  }
  if (!capability_is_valid(arg) || sealing::is_sealed(arg) ||
      !capability_has_perms(arg, perms::DataRw) ||
      capability_get_length(arg) < sizeof(init::AppRequest)) {
    out("[mstress] not invoked with an AppRequest\n");
    return -1;
  }
  s_request = reinterpret_cast<init::AppRequest*>(arg);
  s_ticks_per_us = s_request->ticks_per_us == 0 ? 1 : s_request->ticks_per_us;

  // The command line: this file's options first, then the original's
  // arguments, which go to its `main` as they are.
  int words = 0;
  for (size_t i = 0; i < init::APP_ARGS_MAX; ++i) {
    s_args[i] = s_request->args[i];
  }
  s_args[init::APP_ARGS_MAX - 1] = '\0';
  for (char* cursor = s_args; *cursor != '\0';) {
    if (*cursor == ' ') {
      *cursor++ = '\0';
      continue;
    }
    if (words < WORDS_MAX) {
      s_words[words++] = cursor;
    }
    while (*cursor != '\0' && *cursor != ' ') {
      ++cursor;
    }
  }
  int next = 0;
  size_t heap_bytes = SIGNETOS_MALLOC_HEAP_BYTES;
  bool usage = false;
  while (next < words && s_words[next][0] == '-') {
    if (same(s_words[next], "-w") && next + 1 < words) {
      s_worker = static_cast<int64_t>(number(s_words[next + 1]));
    } else if (same(s_words[next], "-m") && next + 1 < words) {
      heap_bytes = number(s_words[next + 1]) * 1024;
    } else {
      usage = true;
    }
    next += 2;
  }
  if (usage || heap_bytes == 0 || heap_bytes > HEAP_MAX_BYTES) {
    out("[mstress] usage: mstress [-w WORKER] [-m KIB] [THREADS] [SCALE] "
        "[ITER]; KIB at most 4096\n");
    s_request->status = -1;
    return -1;
  }
  int argc = 0;
  s_argv[argc++] = s_name;
  for (; next < words; ++next) {
    s_argv[argc++] = s_words[next];
  }
  s_argv[argc] = nullptr;

  const Capability shared_heap = s_request->caps[0];
  const Capability shared_transfer = s_request->caps[1];
  if (capability_is_valid(shared_heap) ||
      capability_is_valid(shared_transfer)) {
    const uint64_t addr = capability_get_address(shared_transfer);
    const uint64_t base = capability_get_base(shared_transfer);
    const uint64_t room =
        capability_get_length(shared_transfer) - (addr - base);
    if (!sealing::is_sealed_as(OType::QuotaHeap, shared_heap) ||
        !capability_is_valid(shared_transfer) ||
        sealing::is_sealed(shared_transfer) ||
        !capability_has_perms(shared_transfer, perms::DataRw) ||
        (addr & (sizeof(Capability) - 1)) != 0 ||
        room < TRANSFERS * sizeof(void*)) {
      out("[mstress] bad shared heap or transfer capability\n");
      s_request->status = -1;
      return -1;
    }
    malloc_shim::use_heap(shared_heap);
    transfer = reinterpret_cast<volatile void**>(shared_transfer);
  } else {
    malloc_shim::set_heap_bytes(heap_bytes);
    malloc_shim::ready();
    transfer = s_local_transfer;
  }
  THREADS = DEFAULT_THREADS;
  SCALE = DEFAULT_SCALE;
  ITER = DEFAULT_ITER;
  allow_large_objects = false;  // as the original, `main` allows them if SCALE > 100

  init::HeapInfo info{};
  const Capability info_out =
      capability_set_bounds(reinterpret_cast<Capability>(&info), sizeof(info));
  uint64_t heaps = 0;
  if (invoke<int64_t>(s_invoke, rw[SLOT_HEAP_INFO], malloc_shim::heap(),
                      info_out) == init::HEAP_OK) {
    heaps = info.heaps;
  }

  const uint64_t started = now_us();
  const int returned = test_stress_main(argc, s_argv);
  const uint64_t ended = now_us();

  // How many heaps the service holds now (or held at the start): with several
  // instances running, that many heaps exist at once.
  info.heaps = 0;
  if (invoke<int64_t>(s_invoke, rw[SLOT_HEAP_INFO], malloc_shim::heap(),
                      info_out) == init::HEAP_OK &&
      info.heaps > heaps) {
    heaps = info.heaps;
  }

  // The test has freed all it allocated: once the sweeps are over, nothing
  // may be charged to the program's own heap.
  uint64_t charged = 0;
  int64_t unswept = 0;
  if (malloc_shim::owns_heap()) {
    unswept = malloc_shim::settle();
    info.used = ~0ULL;
    invoke<int64_t>(s_invoke, rw[SLOT_HEAP_INFO], malloc_shim::heap(),
                    info_out);
    charged = info.used;
  }

  const bool owned = malloc_shim::owns_heap();
  const uint64_t refused = malloc_shim::refused();
  const uint64_t bad_frees = malloc_shim::bad_frees();
  const int64_t heap_gone = malloc_shim::shutdown();
  const bool passed = returned == 0 && refused == 0 && bad_frees == 0 &&
                      heap_gone == 0 && unswept == 0 && charged == 0;
  if (refused != 0) {
    LineBuffer why;
    begin(why);
    why.str("allocations refused: ");
    why.dec(refused);
    why.str("\n");
    out(why.buf);
  }
  LineBuffer line;
  begin(line);
  line.str(passed ? "passed: " : "FAILED: ");
  line.dec((ended - started) / 1000);
  line.str(" ms, heap.wait calls ");
  line.dec(malloc_shim::waits());
  line.str(", refused frees ");
  line.dec(bad_frees);
  if (unswept != 0) {
    line.str(", sweeps not over");
  } else if (owned) {
    line.str(", bytes still charged ");
    line.dec(charged);
  }
  line.str(", heaps in the service ");
  line.dec(heaps);
  if (heap_gone != 0) {
    line.str(", heap.destroy status -");
    line.dec(static_cast<uint64_t>(-heap_gone));
  }
  line.str("\n");
  out(line.buf);
  const int64_t status = passed ? STATUS_PASSED : STATUS_HEAP;
  s_request->status = status;
  return status;
}

}  // namespace signetos::user
