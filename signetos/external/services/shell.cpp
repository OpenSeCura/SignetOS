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
 * shell.cpp - SignetOS Initial User Shell Compartment
 *
 * Receives application-level VM and thread-memory sub-quotas plus service
 * sentries from `init`; the shell's thread starts with its `quota_sched`
 * handle as the argument.
 *
 * Two ways in:
 *   compartment_main(nullptr)  `init` probing the image: print a banner and
 *                              prove the naming service works.
 *   compartment_main(quota)    the shell's own thread, dispatched by the
 *                              scheduler. A console on the UART.
 *
 * CONSOLE
 *   The shell starts three background workers under 10/6/2 ms-per-second
 *   sub-quotas of its own bandwidth, so the scheduler always has something to
 *   switch between, then waits for keystrokes without spending a cycle on it.
 *   `uart.read` hands over whatever the UART's interrupt handler has buffered
 *   so far; when that is nothing, the shell sleeps in `sched.block`. The next
 *   keystroke's interrupt reaches `uart` (routed through `trap_mgr`), `uart`
 *   invokes `shell_notify_entry` (handed to it in the read request), that
 *   calls `sched.wake` with the shell thread's tid, and the shell is runnable
 *   again. Commands:
 *     help       list commands
 *     stats      CPU time each background worker has received so far
 *     demo       the 300 ms bandwidth self-test described below
 *     fsdemo     the file-system self-test described below
 *     ls [dir], cat, write, append, mkdir, rm, df
 *                files and directories under `/home`, which every path is
 *                relative to: the ADMIN `quota_disk` handle rooted there
 *                that the shell's manifest asks `init` for (SLOT_DISK_QUOTA),
 *                used with the `fs.*` entry points resolved by name
 *     run <f> [args]
 *                a program: a file in `/bin`, read through the second,
 *                read-only handle the manifest asks for (SLOT_BIN_DIR),
 *                loaded into a compartment of its own, given what its own
 *                manifest asks for and this shell's policy allows, and
 *                invoked once on this thread (see "Programs" below and
 *                abi.hpp, "Applications")
 *     shutdown   stop the workers, free their quotas and exit. Nothing is
 *                registered after that, so the dispatcher exits too and the
 *                kernel powers the machine off.
 *   In a build where `init` could not seed `uart.read` nobody is at the
 *   keyboard: the shell then runs the demos and exits by itself.
 *
 * FS DEMO
 *   Writes and reads back a file; makes a directory with a file of the
 *   shell's in it and derives an 8 KiB / 2-inode sub-quota rooted there (its
 *   node paid for from the shell's own VM quota). The sub-quota is shown what
 *   it cannot do: grow past its bytes, create past its inodes, name anything
 *   above its directory, or change the shell's file in it -- though it can
 *   read that. Destroying it unlinks its files and refunds the shell; the
 *   shell's file stays. A directory cannot be removed while it has entries
 *   or a node is rooted at it, and a read-only node is destroyed through the
 *   ADMIN handle its creator kept. The shell's accounting is checked to be
 *   back where it started.
 *
 * RUN DEMO
 *   `run hello.bin` with arguments, expecting status 0 -- which has `run`
 *   read the program's manifest, make `/home/hello` and derive a node of the
 *   shell's quota rooted there for it, open `/home/motd.txt` read-only for
 *   it, and take all of it back when it returns: the demo checks the
 *   directory is gone and the shell's accounting is back where it was. Then
 *   each handle denies the program in its own way: through `/home` it cannot
 *   be named (not under that root, and no `..`), through `/bin` it can be
 *   opened and nothing else -- not written, not removed, not joined by a file
 *   or a directory of the shell's.
 *
 * DEMO
 *   Three interactive workers under 10/6/2 ms-per-100 ms quotas race for
 *   300 ms and report their progress, which should land near 5:3:1. A fourth,
 *   batch-class thread never yields: it uses up the time nobody else has
 *   budget for and proves preemption, since the interactive workers only get
 *   the CPU back from it through the scheduler's tick handler.
 */

#include "runtime.hpp"

namespace signetos::user {
namespace {

uint64_t s_ticks_per_us = 10;  // `time` ticks per us (/cpus timebase-frequency)
constexpr size_t MAX_WORKERS = 4;
constexpr size_t WORKER_STACK = 8 * 1024;
constexpr int DESTROY_RETRIES = 64;
constexpr size_t LINE_MAX = 64;
constexpr uint64_t FOREVER_US = ~0ULL;

// TODO This obviously isn't a real shell or a good shell, it's just enough to
// kind of test some things for now

// --- What the shell asks `init` for (user/manifest.hpp) -----------------------
// Thread memory for its workers; the kernel entries a console that starts
// threads and runs programs is made of; the services it talks to; its place
// on the disk: `/home` as an ADMIN node with all the space and inodes the
// system's own images leave free (DISK entries are met in order, so this one
// takes everything before `/bin` asks for nothing), and `/bin` as a 0-byte
// read-only view of the programs. The system's four root quotas come last,
// optional: `init` exits and scrubs its own table, so the shell is their
// long-lived holder, not their user.
#define SHELL_MANIFEST(X)                                                      \
  M_QUOTA_THREAD(X, THREAD_QUOTA, 160 * 1024)                                  \
  M_SYSCALL(X, SYS_VM_ALLOC, vm_allocate)                                      \
  M_SYSCALL(X, SYS_VM_DEALLOC, vm_deallocate)                                  \
  M_SYSCALL(X, SYS_QUOTA_VM_DERIVE, quota_vm_derive)                           \
  M_SYSCALL(X, SYS_QUOTA_VM_DESTROY, quota_vm_destroy)                         \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)                            \
  M_SYSCALL(X, SYS_COMP_DESTROY, compartment_destroy)                          \
  M_SYSCALL(X, SYS_THREAD_CREATE, thread_create)                               \
  M_SYSCALL(X, SYS_THREAD_KILL, thread_kill)                                   \
  M_SYSCALL(X, SYS_SENTRY, sentry)                                             \
  M_SERVICE(X, UART_SENTRY, "uart")                                            \
  M_SERVICE_OPT(X, UART_READ, "uart.read")                                     \
  M_SERVICE(X, NAMING_LOOKUP, "naming.lookup")                                 \
  M_SERVICE(X, LOADER_SENTRY, "loader")                                        \
  M_DISK(X, DISK_QUOTA, 0, perms::Load | perms::Store,                         \
         ::signetos::init::MANIFEST_ALL, ::signetos::init::MANIFEST_ALL_INODES, \
         "home")                                                               \
  M_DISK(X, BIN_DIR, 0, perms::Load, 0, 0, "bin")                              \
  M_ROOT_OPT(X, ROOT_VM, ::signetos::init::ROOT_VM)                            \
  M_ROOT_OPT(X, ROOT_THREAD_MEM, ::signetos::init::ROOT_THREAD_MEM)            \
  M_ROOT_OPT(X, ROOT_DISK, ::signetos::init::ROOT_DISK)                        \
  M_ROOT_OPT(X, ROOT_SCHED, ::signetos::init::ROOT_SCHED)
// 256 KiB: the shell's own image and tables, its workers' and programs'
// scheduler nodes, and -- `run <file>` -- the buffer a program is read into
// plus the VM sub-quota its compartment lives on while it runs. A program's
// thread is paid from THREAD_QUOTA, like the workers'.
SIGNETOS_MANIFEST(SHELL_MANIFEST, 256 * 1024)

// Demo: 5:3:1 interactive plus a batch hog, 100 us slices, 300 ms.
constexpr size_t DEMO_WORKERS = 4;
constexpr uint32_t DEMO_PERIOD_US = 100'000;
constexpr uint32_t DEMO_BUDGET_US[DEMO_WORKERS] = {10'000, 6'000, 2'000, 20'000};
constexpr uint8_t DEMO_CLASS[DEMO_WORKERS] = {
    init::PRIORITY_INTERACTIVE, init::PRIORITY_INTERACTIVE,
    init::PRIORITY_INTERACTIVE, init::PRIORITY_BATCH};
constexpr uint64_t DEMO_SLICE_US = 100;
constexpr uint64_t DEMO_US = 300'000;

// Background: the same 5:3:1 shape stretched to one-second periods with 2 ms
// slices, so the switching stays visible on a traced console without
// drowning it: nine slices a second, in a burst at the start of each period.
// No hog, so idle time stays with the console.
constexpr size_t BG_WORKERS = 3;
constexpr uint32_t BG_PERIOD_US = 1'000'000;
constexpr uint32_t BG_BUDGET_US[BG_WORKERS] = {10'000, 6'000, 2'000};
constexpr uint8_t BG_CLASS[BG_WORKERS] = {
    init::PRIORITY_INTERACTIVE, init::PRIORITY_INTERACTIVE,
    init::PRIORITY_INTERACTIVE};
constexpr uint64_t BG_SLICE_US = 2'000;

// Shared between the shell thread and one set of workers (all in this
// compartment).
struct Shared {
  Capability invoke;         // sys_compartment_invoke gate
  Capability yield;          // sched.yield
  uint64_t deadline_us;      // workers stop at this time...
  uint64_t stop;             // ...or as soon as this is set
  uint64_t slice_us;         // busy work per iteration
  uint64_t done;             // workers that have finished
  uint64_t count[MAX_WORKERS];  // iterations each worker managed
  bool greedy[MAX_WORKERS];     // never yields (batch class)
};

struct alignas(16) WorkerArg {
  Shared* shared;
  uint64_t index;
  uint64_t pad_;
};

struct WorkerConfig {
  size_t count;
  uint32_t period_us;
  const uint32_t* budget_us;
  const uint8_t* priority;
  uint64_t slice_us;
  uint64_t deadline_us;
};

// A set of workers: what they share, their arguments, their scheduler nodes,
// and the configuration they were started with (for `stats`).
struct WorkerSet {
  Shared shared;
  WorkerArg args[MAX_WORKERS];
  Capability quota[MAX_WORKERS];
  WorkerConfig cfg;
  size_t count;    // configured
  size_t started;  // actually running
};

// Console state. One shell thread, so plain globals.
Capability s_gate_invoke = nullptr;
Capability s_gate_thread_create = nullptr;
Capability s_uart = nullptr;
Capability s_uart_read = nullptr;
Capability s_vm_quota = nullptr;
Capability s_thread_quota = nullptr;
Capability s_my_quota = nullptr;      // ADMIN quota_sched handle from `init`
Capability s_worker_entry = nullptr;  // OType::EntryPoint -> shell_worker_entry
Capability s_sched_derive = nullptr;
Capability s_sched_destroy = nullptr;
Capability s_sched_register = nullptr;
Capability s_sched_yield = nullptr;
Capability s_sched_block = nullptr;
Capability s_sched_wake = nullptr;
Capability s_notify_entry = nullptr;  // OType::EntryPoint -> shell_notify_entry
uint64_t s_my_tid = 0;                // the shell thread, as `sched.wake` knows it

WorkerSet s_background;
WorkerSet s_demo;

inline uint64_t now_us() {
  uint64_t t;
  __asm__ volatile("csrr %0, time" : "=r"(t));
  return t / s_ticks_per_us;
}

template <typename T>
Capability bounded(T* p) {
  return capability_set_bounds(reinterpret_cast<Capability>(p), sizeof(T));
}

bool str_eq(const char* a, const char* b) {
  while (*a != '\0' && *a == *b) {
    ++a;
    ++b;
  }
  return *a == *b;
}

void out(const char* msg) { print(s_gate_invoke, s_uart, msg); }

void out_dec(const char* prefix, uint64_t value, const char* suffix) {
  print_dec(s_gate_invoke, s_uart, prefix, value, suffix);
}

void yield() { invoke<int64_t>(s_gate_invoke, s_sched_yield); }

// Sleeps until `shell_notify_entry` has run (or had already run since the
// last time: the scheduler remembers a wake that arrives early).
void block() { invoke<int64_t>(s_gate_invoke, s_sched_block, 0ULL); }

// --- Files: clients of fs.* ----------------------------------------------------

// The shell's place on the disk, both handles asked of `init` in the manifest
// (abi.hpp, "File system"): an ADMIN `quota_disk` rooted at `/home`, which
// every path a file command takes is relative to, and an OP one rooted at
// `/bin` with no budget -- a read-only view of the programs `run` loads. And
// the file system's entry points, resolved by name.
Capability s_disk_quota = nullptr;
Capability s_bin_quota = nullptr;
Capability s_fs_derive = nullptr;
Capability s_fs_destroy = nullptr;
Capability s_fs_query = nullptr;
Capability s_fs_create = nullptr;
Capability s_fs_mkdir = nullptr;
Capability s_fs_open = nullptr;
Capability s_fs_close = nullptr;
Capability s_fs_read = nullptr;
Capability s_fs_write = nullptr;
Capability s_fs_unlink = nullptr;
Capability s_fs_list = nullptr;
bool s_fs_ready = false;

// Buffers that cross into `fs` live here rather than on the (narrowed) stack.
constexpr size_t LIST_MAX = 16;
constexpr size_t DATA_MAX = 8192;
alignas(16) init::FsDirEntry s_entries[LIST_MAX];
alignas(16) uint8_t s_data[DATA_MAX];
// Every file handle one node can hold at once (the fs demo fills a node).
alignas(16) Capability s_handles[init::FS_OPEN_PER_NODE];

// Compartments link no C library: a request too large for the compiler to
// zero inline (`T x{}`) would otherwise become a call to `memset`. The
// path-carrying `FsDeriveRequest` is that large, so it is zeroed by this loop
// (which stays a loop under -ffreestanding) and filled field by field.
void zero_bytes(void* p, size_t n) {
  auto* d = static_cast<uint8_t*>(p);
  for (size_t i = 0; i < n; ++i) {
    d[i] = 0;
  }
}

// A request's FS_PATH_MAX-byte path field: `path`, truncated if need be, then
// NULs to the end.
void set_path(char* dst, const char* path) {
  size_t i = 0;
  for (; i + 1 < init::FS_PATH_MAX && path[i] != '\0'; ++i) {
    dst[i] = path[i];
  }
  for (; i < init::FS_PATH_MAX; ++i) {
    dst[i] = '\0';
  }
}

const char* fs_status_name(int64_t st) {
  switch (st) {
    case init::FS_OK: return "OK";
    case init::FS_BAD_REQUEST: return "bad request";
    case init::FS_INVALID_QUOTA: return "invalid quota handle";
    case init::FS_PERMISSION: return "permission denied";
    case init::FS_QUOTA: return "quota exceeded";
    case init::FS_NO_MEMORY: return "out of memory";
    case init::FS_BUSY: return "busy";
    case init::FS_NOT_FOUND: return "not found";
    case init::FS_EXISTS: return "already exists";
    case init::FS_INVALID_FILE: return "invalid file handle";
    case init::FS_TOO_LARGE: return "file too large";
    case init::FS_IO_ERROR: return "I/O error";
    case init::FS_DISK_FULL: return "disk full";
    case init::FS_NOT_MOUNTED: return "not mounted";
    case init::FS_NOT_DIR: return "not a directory";
    case init::FS_IS_DIR: return "is a directory";
    case init::FS_NOT_EMPTY: return "directory not empty";
    default: return "unknown status";
  }
}

void fs_fail(const char* what, int64_t st) {
  out("[shell]    ");
  out(what);
  out(": ");
  out(fs_status_name(st));
  out("\n");
}

// Every path below is relative to the root directory of the handle it goes
// with: `/home` for `s_disk_quota`, `/bin` for `s_bin_quota`, wherever a
// sub-quota was derived at for that sub-quota.

// fs.create or fs.open (`entry` picks which) of `path` under `quota`, for a
// handle with `file_perms` (perms::Load, or Load | Store); the file's size,
// if wanted, comes back in `*out_size`.
int64_t fs_open_with(Capability entry, Capability quota, const char* path,
                     Capability* out_file, uint64_t* out_size = nullptr,
                     uint32_t file_perms = perms::Load | perms::Store) {
  if (out_size != nullptr) {
    *out_size = 0;
  }
  Capability f = invoke<Capability>(
      s_gate_invoke, entry, quota, ro_str(path), file_perms,
      out_size != nullptr ? bounded(out_size) : nullptr);
  if (capability_is_valid(f)) {
    *out_file = f;
    return init::FS_OK;
  }
  *out_file = nullptr;
  return init::cap_error(f, init::FS_BAD_REQUEST);
}

int64_t fs_close(Capability file) {
  return invoke<int64_t>(s_gate_invoke, s_fs_close, file);
}

// fs.read or fs.write (`entry`) of `length` bytes at `offset`.
int64_t fs_io(Capability entry, Capability file, void* buf, uint64_t offset,
              uint64_t length, uint64_t* done) {
  Capability b = capability_set_bounds(reinterpret_cast<Capability>(buf), length);
  const int64_t res =
      invoke<int64_t>(s_gate_invoke, entry, file, b, offset, length);
  if (res >= 0) {
    if (done != nullptr) {
      *done = static_cast<uint64_t>(res);
    }
    return init::FS_OK;
  }
  if (done != nullptr) {
    *done = 0;
  }
  return res;
}

// fs.unlink or fs.mkdir (`entry`): the two take the same arguments.
int64_t fs_path_op(Capability entry, Capability quota, const char* path) {
  return invoke<int64_t>(s_gate_invoke, entry, quota, ro_str(path));
}

int64_t fs_unlink(Capability quota, const char* path) {
  return fs_path_op(s_fs_unlink, quota, path);
}

int64_t fs_mkdir(Capability quota, const char* path) {
  return fs_path_op(s_fs_mkdir, quota, path);
}

// Lists the directory `path` under `quota` into `s_entries`; `*total` counts
// its entries whether or not they fit.
int64_t fs_list(Capability quota, const char* path, uint64_t* count,
                uint64_t* total) {
  *count = 0;
  *total = 0;
  Capability ents = capability_set_bounds(
      reinterpret_cast<Capability>(&s_entries[0]), sizeof(s_entries));
  const int64_t res = invoke<int64_t>(s_gate_invoke, s_fs_list, quota,
                                      ro_str(path), ents,
                                      static_cast<uint64_t>(LIST_MAX),
                                      bounded(total));
  if (res < 0) {
    return res;
  }
  *count = static_cast<uint64_t>(res);
  return init::FS_OK;
}

int64_t fs_query(Capability quota, init::FsQueryRequest& req) {
  req.quota = quota;
  req.status = init::FS_BAD_REQUEST;
  return invoke<int64_t>(s_gate_invoke, s_fs_query, bounded(&req));
}

// A sub-quota of `parent` rooted at the directory `path` names under the
// parent's own ("" for the parent's), its node paid for from the shell's own
// VM quota. ADMIN unless `handle_perms` lacks Store; either way the node's
// ADMIN handle comes back in `*out_admin` if asked, since that is the only
// thing it can be destroyed with. `flags`: FS_DERIVE_ADOPT or 0.
int64_t fs_derive(Capability parent, const char* path, uint64_t bytes,
                  uint32_t inodes, Capability* out_quota,
                  uint32_t handle_perms = perms::Load | perms::Store,
                  Capability* out_admin = nullptr, uint64_t flags = 0) {
  init::FsDeriveRequest req;
  zero_bytes(&req, sizeof(req));
  req.parent = parent;
  req.node_funding = s_vm_quota;
  set_path(req.path, path);
  req.limit_bytes = bytes;
  req.limit_inodes = inodes;
  req.perms = handle_perms;
  req.status = init::FS_BAD_REQUEST;
  req.flags = flags;
  invoke<int64_t>(s_gate_invoke, s_fs_derive, bounded(&req));
  *out_quota = req.out_quota;
  if (out_admin != nullptr) {
    *out_admin = req.out_admin;
  }
  return req.status;
}

int64_t fs_destroy(Capability quota) {
  return invoke<int64_t>(s_gate_invoke, s_fs_destroy, quota);
}

// The size of the file at `path`; false if the shell cannot open it.
bool file_size(const char* path, uint64_t* size) {
  Capability file = nullptr;
  if (fs_open_with(s_fs_open, s_disk_quota, path, &file, size) != init::FS_OK) {
    return false;
  }
  fs_close(file);
  return true;
}

size_t str_len(const char* s) {
  size_t n = 0;
  while (s[n] != '\0') {
    n += 1;
  }
  return n;
}

void banner(Capability gate_invoke, Capability uart_sentry,
            Capability naming_lookup) {
  print(gate_invoke, uart_sentry,
        "[shell]    User shell skeleton initialized (VM + thread quotas & service sentries)\n");

  // Resolve the console through the registry and print through what it
  // returned: proof that lookup hands out a usable entry point.
  int64_t status = init::NAMING_BAD_REQUEST;
  Capability uart_by_name =
      lookup_name(gate_invoke, naming_lookup, "uart", &status);
  if (status == init::NAMING_OK && capability_is_valid(uart_by_name)) {
    print(gate_invoke, uart_by_name,
          "[shell]    naming.lookup(\"uart\") -> printing through the returned entry point\n");
  } else {
    print(gate_invoke, uart_sentry, "[shell]    naming.lookup(\"uart\") FAILED\n");
  }
  if (lookup_name(gate_invoke, naming_lookup, "no-such-service", &status) ==
          nullptr &&
      status == init::NAMING_NOT_FOUND) {
    print(gate_invoke, uart_sentry,
          "[shell]    naming.lookup(\"no-such-service\") -> NOT_FOUND as expected\n");
  }
}

// --- Workers -----------------------------------------------------------------

// One node per worker, carved out of the shell's own bandwidth; the pages are
// paid for from the shell's VM quota. Stops at the first failure and returns
// how many workers are running.
size_t start_workers(WorkerSet& set, const WorkerConfig& cfg) {
  using FnThreadCreate = decltype(&sys_thread_create);

  Shared& sh = set.shared;
  sh.invoke = s_gate_invoke;
  sh.yield = s_sched_yield;
  sh.deadline_us = cfg.deadline_us;
  sh.stop = 0;
  sh.slice_us = cfg.slice_us;
  sh.done = 0;
  set.cfg = cfg;
  set.count = cfg.count;
  set.started = 0;
  for (size_t i = 0; i < MAX_WORKERS; ++i) {
    sh.count[i] = 0;
    sh.greedy[i] = i < cfg.count && cfg.priority[i] == init::PRIORITY_BATCH;
    set.quota[i] = nullptr;
  }

  for (size_t i = 0; i < cfg.count; ++i) {
    init::SchedDeriveRequest dreq{};
    dreq.parent = s_my_quota;
    dreq.node_funding = s_vm_quota;
    dreq.budget_us = cfg.budget_us[i];
    dreq.period_us = cfg.period_us;
    dreq.policy_id = init::POLICY_SCHED_DEFAULT;
    dreq.perms = perms::Load | perms::Store;
    dreq.priority_class = cfg.priority[i];
    dreq.status = init::SCHED_BAD_REQUEST;
    invoke<int64_t>(s_gate_invoke, s_sched_derive, bounded(&dreq));
    if (dreq.status != init::SCHED_OK) {
      out_dec("[shell]    sched.quota_derive FAILED, status ",
              static_cast<uint64_t>(-dreq.status), "\n");
      break;
    }
    set.quota[i] = dreq.out_quota;

    set.args[i].shared = &sh;
    set.args[i].index = i;
    // `args[i]` sits in this compartment's `.bss`, not on a stack, so the
    // initial argument is a global capability the kernel will accept.
    Capability t = syscall::call<FnThreadCreate>(
        s_gate_invoke, s_gate_thread_create, s_thread_quota, WORKER_STACK,
        s_worker_entry, bounded(&set.args[i]));
    if (!sealing::is_sealed_as(OType::Thread, t)) {
      out("[shell]    worker thread_create FAILED\n");
      break;
    }
    const int64_t tid =
        invoke<int64_t>(s_gate_invoke, s_sched_register, t, set.quota[i]);
    if (tid <= 0) {
      out("[shell]    sched.thread_register FAILED\n");
      break;
    }
    set.started += 1;
  }
  return set.started;
}

// Waits for every started worker to finish. `yield` hands the CPU over
// whenever anyone else may run.
void wait_workers(WorkerSet& set) {
  while (__atomic_load_n(&set.shared.done, __ATOMIC_SEQ_CST) < set.started) {
    yield();
  }
}

void stop_workers(WorkerSet& set) {
  __atomic_store_n(&set.shared.stop, 1, __ATOMIC_SEQ_CST);
  wait_workers(set);
}

// Tears the nodes down. A worker that has bumped `done` may not have exited
// yet, in which case destroy answers BUSY: yield and retry.
size_t destroy_workers(WorkerSet& set) {
  size_t destroyed = 0;
  for (size_t i = 0; i < set.count; ++i) {
    if (!capability_is_valid(set.quota[i])) {
      continue;
    }
    for (int attempt = 0; attempt < DESTROY_RETRIES; ++attempt) {
      const int64_t st =
          invoke<int64_t>(s_gate_invoke, s_sched_destroy, set.quota[i]);
      if (st == init::SCHED_OK) {
        destroyed += 1;
        set.quota[i] = nullptr;
        break;
      }
      if (st != init::SCHED_BUSY) {
        break;
      }
      yield();
    }
  }
  set.started = 0;
  return destroyed;
}

// --- Commands ----------------------------------------------------------------

void run_demo() {
  const WorkerConfig cfg{DEMO_WORKERS, DEMO_PERIOD_US, DEMO_BUDGET_US,
                         DEMO_CLASS, DEMO_SLICE_US, now_us() + DEMO_US};
  const size_t started = start_workers(s_demo, cfg);
  out_dec("[shell]    Started ", started,
          " threads: interactive 10/6/2 ms + batch 20 ms per 100 ms; "
          "waiting 300 ms...\n");
  wait_workers(s_demo);

  const Shared& sh = s_demo.shared;
  out_dec("[shell]    interactive worker0 (10 ms): ", sh.count[0], " x 100 us\n");
  out_dec("[shell]    interactive worker1 ( 6 ms): ", sh.count[1], " x 100 us\n");
  out_dec("[shell]    interactive worker2 ( 2 ms): ", sh.count[2], " x 100 us\n");
  out_dec("[shell]    batch hog, never yields (20 ms): ", sh.count[3],
          " x 100 us (plus idle time)\n");
  const bool ordered = started == DEMO_WORKERS && sh.count[2] > 0 &&
                       sh.count[0] > sh.count[1] && sh.count[1] > sh.count[2];
  out(ordered ? "[shell]    Bandwidth ordering OK (worker0 > worker1 > worker2)\n"
              : "[shell]    Bandwidth ordering WRONG\n");

  const size_t destroyed = destroy_workers(s_demo);
  out_dec("[shell]    Destroyed ", destroyed, " demo quotas\n");
}

void print_stats() {
  const WorkerSet& set = s_background;
  const Shared& sh = set.shared;
  if (set.started == 0) {
    out("[shell]    no background workers running\n");
    return;
  }
  for (size_t i = 0; i < set.started; ++i) {
    out_dec("[shell]    worker", i, sh.greedy[i] ? " (batch hog, " : " (");
    out_dec("", set.cfg.budget_us[i] / 1000, " ms per ");
    out_dec("", set.cfg.period_us / 1000, " ms): ");
    out_dec("", sh.count[i] * sh.slice_us / 1000,
            sh.greedy[i] ? " ms of CPU so far (plus idle time)\n"
                         : " ms of CPU so far\n");
  }
}

// --- File commands -------------------------------------------------------------

// Splits `line` at the first blank: returns the first word (NUL-terminated in
// place) and leaves `*rest` on the remainder, leading blanks skipped.
char* first_word(char* line, char** rest) {
  while (*line == ' ') {
    ++line;
  }
  char* word = line;
  while (*line != '\0' && *line != ' ') {
    ++line;
  }
  if (*line != '\0') {
    *line++ = '\0';
    while (*line == ' ') {
      ++line;
    }
  }
  *rest = line;
  return word;
}

bool fs_available() {
  if (!s_fs_ready) {
    out("[shell]    no file system available\n");
  }
  return s_fs_ready;
}

// `ls [dir]`: the entries of `dir` (the shell's own root, `/home`, when
// empty). A directory shows with a trailing '/'; a file with its size; and
// anything that is not the shell's own says so, since in view is not the same
// as the shell's to change (abi.hpp, FS_OWNER_*).
void cmd_ls(const char* path) {
  if (!fs_available()) {
    return;
  }
  uint64_t count = 0;
  uint64_t total = 0;
  const int64_t st = fs_list(s_disk_quota, path, &count, &total);
  if (st != init::FS_OK) {
    fs_fail("ls", st);
    return;
  }
  for (uint64_t i = 0; i < count; ++i) {
    const init::FsDirEntry& e = s_entries[i];
    out("  ");
    out(e.name);
    if (e.is_dir != 0) {
      out("/");
    } else {
      out_dec("  ", e.size, " bytes");
    }
    out(e.owner == init::FS_OWNER_SELF    ? "\n"
        : e.owner == init::FS_OWNER_CHILD ? " (sub-quota)\n"
                                          : " (read-only)\n");
  }
  out_dec("[shell]    ", total, " entries\n");
}

void cmd_mkdir(const char* path) {
  if (!fs_available()) {
    return;
  }
  if (*path == '\0') {
    out("[shell]    usage: mkdir <dir>\n");
    return;
  }
  const int64_t st = fs_mkdir(s_disk_quota, path);
  if (st != init::FS_OK) {
    fs_fail("mkdir", st);
  }
}

void cmd_cat(const char* name) {
  if (!fs_available()) {
    return;
  }
  if (*name == '\0') {
    out("[shell]    usage: cat <name>\n");
    return;
  }
  Capability file = nullptr;
  int64_t st = fs_open_with(s_fs_open, s_disk_quota, name, &file);
  if (st != init::FS_OK) {
    fs_fail("cat", st);
    return;
  }
  uint64_t offset = 0;
  for (;;) {
    uint64_t got = 0;
    st = fs_io(s_fs_read, file, s_data, offset, DATA_MAX - 1, &got);
    if (st != init::FS_OK) {
      fs_fail("cat", st);
      break;
    }
    if (got == 0) {
      break;
    }
    s_data[got] = '\0';
    out(reinterpret_cast<const char*>(s_data));
    offset += got;
  }
  fs_close(file);
}

// `write` replaces the file; `append` adds to its end. Both create it.
void cmd_write(const char* name, const char* text, bool append) {
  if (!fs_available()) {
    return;
  }
  if (*name == '\0') {
    out(append ? "[shell]    usage: append <name> <text>\n"
               : "[shell]    usage: write <name> <text>\n");
    return;
  }
  uint64_t offset = 0;
  if (append) {
    file_size(name, &offset);  // 0 if it does not exist yet
  } else {
    fs_unlink(s_disk_quota, name);  // NOT_FOUND is fine
  }
  Capability file = nullptr;
  int64_t st = fs_open_with(s_fs_create, s_disk_quota, name, &file);
  if (st == init::FS_EXISTS && append) {
    st = fs_open_with(s_fs_open, s_disk_quota, name, &file);
  }
  if (st != init::FS_OK) {
    fs_fail(append ? "append" : "write", st);
    return;
  }
  size_t len = str_len(text);
  if (len > DATA_MAX - 1) {
    len = DATA_MAX - 1;
  }
  for (size_t i = 0; i < len; ++i) {
    s_data[i] = static_cast<uint8_t>(text[i]);
  }
  s_data[len++] = '\n';
  uint64_t done = 0;
  st = fs_io(s_fs_write, file, s_data, offset, len, &done);
  if (st != init::FS_OK) {
    fs_fail(append ? "append" : "write", st);
  } else {
    out_dec("[shell]    ", done, " bytes written\n");
  }
  fs_close(file);
}

// A file, or a directory with nothing in it (and no sub-quota rooted at it).
void cmd_rm(const char* path) {
  if (!fs_available()) {
    return;
  }
  if (*path == '\0') {
    out("[shell]    usage: rm <path>\n");
    return;
  }
  const int64_t st = fs_unlink(s_disk_quota, path);
  if (st != init::FS_OK) {
    fs_fail("rm", st);
  }
}

void print_quota(const char* label, const init::FsQueryRequest& q) {
  out(label);
  out_dec("", q.used_bytes / 1024, " KiB used + ");
  out_dec("", q.delegated_bytes / 1024, " KiB delegated of ");
  out_dec("", q.limit_bytes / 1024, " KiB; ");
  out_dec("", q.used_inodes, " + ");
  out_dec("", q.delegated_inodes, " of ");
  out_dec("", q.limit_inodes, " files\n");
}

void cmd_df() {
  if (!fs_available()) {
    return;
  }
  init::FsQueryRequest q{};
  const int64_t st = fs_query(s_disk_quota, q);
  if (st != init::FS_OK) {
    fs_fail("df", st);
    return;
  }
  print_quota("[shell]    disk quota: ", q);
}

// --- Programs ------------------------------------------------------------------

// `run <file> [args]`: a file in `/bin`, loaded into a compartment of its own
// and run once, on a thread of its own (abi.hpp, "Applications"; THE
// PROGRAM'S THREAD below). In order, each step undone on the way out whatever
// happens after it:
//   1. fs.open and fs.read the file -- through `s_bin_quota`, the read-only
//      handle on `/bin` -- into a page-granular, zeroed allocation of the
//      shell's: the same shape as a packaged image, so `loader` can take it
//      as one (see `DiskImages` in init.cpp, which does the same);
//   2. read its manifest (user/manifest.hpp) and grant it, entry by entry,
//      by the policy below -- this is the shell acting as a launcher, and
//      the whole of what the program will be able to reach is decided here;
//   3. a VM sub-quota of the shell's for the program to live on, as large as
//      the manifest asks within APP_VM_MAX;
//   4. `loader`: compartment, code, entry sentry -- seeded with `s_app_seeds`,
//      entry i in slot RW_SLOT_SEED_BASE + i. There is no directory to ask: a
//      program holds what its creator put in its table and nothing else;
//   5. start its thread -- entry: the program's entry point, argument: an
//      `AppRequest` carrying the arguments -- on a `quota_sched` node of its
//      own, and sleep until the thread has ended; its status comes back in
//      the block;
//   6. destroy the compartment, destroy the quota, release the buffer, and
//      take back what step 2 granted: destroy the nodes (which removes the
//      directories and everything the program put in them) and close the
//      files.
// Everything a program had is gone when `run` returns, and INIT.2 (the
// kernel's own test) confirms nothing of it leaked.
//
// THE POLICY: what a program may ask this shell for
//   syscall  `compartment_invoke` only -- the switcher, without which nothing
//            can be called. No allocation, no sealing, no threads: a program
//            lives on what the shell gave it, on the one thread `run` makes
//            for it (THE PROGRAM'S THREAD, below).
//   service  the console (`uart`) and the file operations: fs.open, read,
//            write, close, create, mkdir, unlink, list and quota_query.
//            Not `fs.quota_derive`/`quota_destroy`: a node a program derived
//            would be paid for from its VM quota, and could keep that quota
//            -- and its directory -- from being destroyed when it returns.
//            Not `naming.lookup`, `loader`, `sched`, `uart.read`: nothing it
//            could reach further with.
//   disk     a directory of its own under `/home`: `/home/<prog>` (the file
//            name without `.bin`), or `/home/<prog>/<name>` if the entry
//            names a sub-directory. Made if need be, then a node of the
//            shell's quota derived rooted there, with the limits asked for up
//            to APP_DISK_MAX_BYTES / APP_DISK_MAX_INODES (MANIFEST_ALL asks
//            for the maximum), the handle permissions asked for, and the
//            directory adopted, so that destroying the node when the program
//            returns removes the directory with it. Ephemeral, then: a
//            program's files last as long as the program.
//   file     a file under `/home`, by path, opened through the shell's own
//            handle with the permissions asked for -- read-only is what a
//            program is usually handed -- and closed when it returns. A file
//            the shell could not open is simply not granted.
//   anything else (devices, interrupts, exceptions, thread memory, root
//            quotas, kinds this shell does not know) is refused.
// A REQUIRED entry refused means the program is not started, and `run` says
// which entry; an optional one refused is a null slot.
constexpr int64_t RUN_NOT_RUN = -1;                   // *out_status if it never ran
constexpr size_t APP_VM_DEFAULT = 64 * 1024;          // a manifest asking for 0
constexpr size_t APP_VM_MAX = 128 * 1024;             // the most a program may ask
constexpr uint64_t APP_DISK_MAX_BYTES = 256 * 1024;   // per DISK entry
constexpr uint32_t APP_DISK_MAX_INODES = 32;

// THE PROGRAM'S THREAD
//   A program does not run on the shell's thread: `run` makes it a thread of
//   its own whose entry is the program's own entry point, so the thread
//   starts inside the program -- its first compartment, depth 0 -- and
//   everything the program calls nests from there (program -> fs -> blk ->
//   sched.block is three calls, where on the shell's thread it was four).
//   When the entry returns the thread ends, and
//   so does a fault in the program: it ends the program's thread, never the
//   shell's. The thread is paid from the shell's thread memory and scheduled
//   under a `quota_sched` node of its own, APP_BUDGET_US per APP_PERIOD_US
//   carved out of the shell's bandwidth: a program is preempted like any
//   other thread and cannot take more of the CPU than that. The shell sleeps
//   meanwhile and knows the program is done when the node can be destroyed --
//   `sched.quota_destroy` answers BUSY while a thread is still registered on
//   it, and the scheduler unregisters a thread when it ends.
constexpr size_t APP_STACK = 16 * 1024;
constexpr uint32_t APP_BUDGET_US = 20'000;
constexpr uint32_t APP_PERIOD_US = 100'000;
constexpr uint64_t APP_POLL_US = 5'000;  // how often the shell looks again

// In `.bss`, not on the stack: `sys_compartment_create` refuses a seed array
// that overlaps the stack it runs on. One slot per manifest entry, and beside
// it what `run` must take back for that entry when the program returns.
alignas(16) Capability s_app_seeds[init::MANIFEST_MAX];
alignas(16) Capability s_app_nodes[init::MANIFEST_MAX];  // DISK: the ADMIN handle
alignas(16) Capability s_app_files[init::MANIFEST_MAX];  // FILE: the open file
alignas(16) init::AppRequest s_app_req;
bool s_run_ready = false;
Capability s_self_comp = nullptr;
Capability s_loader = nullptr;
Capability s_gate_vm_alloc = nullptr;
Capability s_gate_vm_dealloc = nullptr;
Capability s_gate_q_derive = nullptr;
Capability s_gate_q_destroy = nullptr;
Capability s_gate_comp_destroy = nullptr;
Capability s_gate_thread_kill = nullptr;

// Sleeps until `us` have passed, or until something wakes the shell first
// (a keystroke); callers loop on whatever they are waiting for.
void sleep_us(uint64_t us) {
  invoke<int64_t>(s_gate_invoke, s_sched_block, us);
}

// A `quota_sched` node of the shell's for one program, or null.
Capability derive_app_node() {
  init::SchedDeriveRequest req{};
  req.parent = s_my_quota;
  req.node_funding = s_vm_quota;
  req.budget_us = APP_BUDGET_US;
  req.period_us = APP_PERIOD_US;
  req.policy_id = init::POLICY_SCHED_DEFAULT;
  req.perms = perms::Load | perms::Store;
  req.priority_class = init::PRIORITY_INTERACTIVE;
  req.status = init::SCHED_BAD_REQUEST;
  invoke<int64_t>(s_gate_invoke, s_sched_derive, bounded(&req));
  return req.status == init::SCHED_OK ? req.out_quota : nullptr;
}

// sched.quota_destroy of `node`: SCHED_OK, or SCHED_BUSY while a thread is
// still registered on it.
int64_t destroy_sched_node(Capability node) {
  return invoke<int64_t>(s_gate_invoke, s_sched_destroy, node);
}

// Starts the program's thread at `entry` with `s_app_req`, registered on
// `node`. False if it could not be started, in which case nothing of it is
// left running.
bool start_app_thread(Capability entry, Capability node) {
  using FnThreadCreate = decltype(&sys_thread_create);
  using FnThreadKill = decltype(&sys_thread_kill);
  // `s_app_req` sits in `.bss`, not on a stack, so it is a global capability
  // the kernel will take as the initial argument.
  Capability t = syscall::call<FnThreadCreate>(
      s_gate_invoke, s_gate_thread_create, s_thread_quota, APP_STACK, entry,
      bounded(&s_app_req));
  if (!sealing::is_sealed_as(OType::Thread, t)) {
    out("[shell]    run: no thread memory left for a program\n");
    return false;
  }
  const int64_t tid = invoke<int64_t>(s_gate_invoke, s_sched_register, t, node);
  if (tid <= 0) {
    // Never dispatched, so never inside anything: safe to end here.
    syscall::call<FnThreadKill>(s_gate_invoke, s_gate_thread_kill, t);
    out("[shell]    run: the scheduler would not take the program's thread\n");
    return false;
  }
  return true;
}

// Sleeps until the program's thread has ended -- its node destroys -- and
// says whether it did. Anything but BUSY from destroy ends the wait.
bool wait_app_thread(Capability node) {
  for (;;) {
    sleep_us(APP_POLL_US);
    const int64_t st = destroy_sched_node(node);
    if (st == init::SCHED_OK) {
      return true;
    }
    if (st != init::SCHED_BUSY) {
      out_dec("[shell]    run: WARNING: the program's scheduler node would "
              "not go, status -", static_cast<uint64_t>(-st), "\n");
      return false;
    }
  }
}

// Step 1: `name`, in `/bin`, read whole into a fresh page-granular, zeroed
// allocation of the shell's, or null, the reason already printed under
// `what`.
Capability read_image(const char* what, const char* name) {
  using FnAlloc = decltype(&sys_vm_allocate);
  using FnDealloc = decltype(&sys_vm_deallocate);
  Capability file = nullptr;
  uint64_t size = 0;
  int64_t st = fs_open_with(s_fs_open, s_bin_quota, name, &file, &size,
                            perms::Load);
  if (st != init::FS_OK) {
    fs_fail(what, st);
    return nullptr;
  }
  bool ok = size >= sizeof(init::CompartmentImageHeader) &&
            size <= init::FS_MAX_FILE_BYTES;
  if (!ok) {
    out("[shell]    ");
    out(what);
    out(": not a program (size)\n");
  }
  Capability image = nullptr;
  if (ok) {
    const size_t bytes =
        (static_cast<size_t>(size) + vm::PAGE_SIZE - 1) & ~(vm::PAGE_SIZE - 1);
    image = syscall::call<FnAlloc>(s_gate_invoke, s_gate_vm_alloc, s_self_comp,
                                   s_vm_quota, bytes, FLAG_ZERO);
    ok = capability_is_valid(image);
    if (!ok) {
      out("[shell]    ");
      out(what);
      out(": out of memory for the image\n");
    }
  }
  if (ok) {
    uint64_t got = 0;
    st = fs_io(s_fs_read, file, image, 0, size, &got);
    ok = st == init::FS_OK && got == size;
    if (!ok) {
      fs_fail(what, st == init::FS_OK ? init::FS_IO_ERROR : st);
      syscall::call<FnDealloc>(s_gate_invoke, s_gate_vm_dealloc, s_self_comp,
                               s_vm_quota, image);
      image = nullptr;
    }
  }
  fs_close(file);
  return image;
}

// The file-system entry points a program may ask for by name, or null.
Capability program_service(const char* name) {
  if (str_eq(name, "uart")) return s_uart;
  if (str_eq(name, "fs.open")) return s_fs_open;
  if (str_eq(name, "fs.read")) return s_fs_read;
  if (str_eq(name, "fs.write")) return s_fs_write;
  if (str_eq(name, "fs.close")) return s_fs_close;
  if (str_eq(name, "fs.create")) return s_fs_create;
  if (str_eq(name, "fs.mkdir")) return s_fs_mkdir;
  if (str_eq(name, "fs.unlink")) return s_fs_unlink;
  if (str_eq(name, "fs.list")) return s_fs_list;
  if (str_eq(name, "fs.quota_query")) return s_fs_query;
  return nullptr;
}

// `<prog>` or `<prog>/<sub>` into `dst` (FS_PATH_MAX): the program's file
// name without a trailing `.bin`, then the entry's own name. False if it
// would not fit.
bool program_dir(char* dst, const char* prog, const char* sub) {
  size_t n = 0;
  while (prog[n] != '\0') {
    ++n;
  }
  if (n > 4 && prog[n - 4] == '.' && prog[n - 3] == 'b' && prog[n - 2] == 'i' &&
      prog[n - 1] == 'n') {
    n -= 4;
  }
  size_t pos = 0;
  for (size_t i = 0; i < n; ++i) {
    if (pos + 1 >= init::FS_PATH_MAX) return false;
    dst[pos++] = prog[i];
  }
  if (sub[0] != '\0') {
    if (pos + 1 >= init::FS_PATH_MAX) return false;
    dst[pos++] = '/';
    for (size_t i = 0; sub[i] != '\0'; ++i) {
      if (pos + 1 >= init::FS_PATH_MAX) return false;
      dst[pos++] = sub[i];
    }
  }
  dst[pos] = '\0';
  return pos > 0;
}

// `mkdir -p` of `path` under `/home`: each component in turn, an existing one
// being fine. False on anything else.
bool mkdir_path(const char* path) {
  char buf[init::FS_PATH_MAX];
  for (size_t i = 0;; ++i) {
    const char c = path[i];
    if (c == '/' || c == '\0') {
      buf[i] = '\0';
      const int64_t st = fs_mkdir(s_disk_quota, buf);
      if (st != init::FS_OK && st != init::FS_EXISTS) {
        return false;
      }
      if (c == '\0') {
        return true;
      }
    }
    buf[i] = c;
  }
}

// Step 2, one DISK entry: the directory, and a node of the shell's rooted
// there. The handle asked for goes to the seed, the ADMIN handle to
// `s_app_nodes` for the way out.
Capability grant_disk(const char* prog, const init::ManifestEntry& e,
                      Capability* out_admin) {
  *out_admin = nullptr;
  if ((e.perms & perms::Load) == 0) {
    return nullptr;
  }
  char path[init::FS_PATH_MAX];
  if (!program_dir(path, prog, e.name) || !mkdir_path(path)) {
    return nullptr;
  }
  uint64_t bytes = e.amount == init::MANIFEST_ALL ? APP_DISK_MAX_BYTES : e.amount;
  if (bytes > APP_DISK_MAX_BYTES) bytes = APP_DISK_MAX_BYTES;
  bytes = (bytes + init::FS_BLOCK_BYTES - 1) & ~(init::FS_BLOCK_BYTES - 1);
  uint32_t inodes =
      e.count == init::MANIFEST_ALL_INODES ? APP_DISK_MAX_INODES : e.count;
  if (inodes > APP_DISK_MAX_INODES) inodes = APP_DISK_MAX_INODES;
  Capability handle = nullptr;
  const int64_t st = fs_derive(s_disk_quota, path, bytes, inodes, &handle,
                               e.perms & (perms::Load | perms::Store), out_admin,
                               init::FS_DERIVE_ADOPT);
  if (st != init::FS_OK) {
    fs_fail("run: disk entry", st);
    return nullptr;
  }
  return handle;
}

// Step 2: the manifest, entry by entry, into `s_app_seeds` by the policy
// above. True if every REQUIRED entry was met; the first that was not is
// named on the console. Prints the grants on one line either way.
bool grant_manifest(const char* prog, const init::Manifest& m) {
  bool ok = true;
  out("[shell]    ");
  out(prog);
  out(" gets:");
  for (uint32_t i = 0; i < m.count; ++i) {
    const init::ManifestEntry& e = m.entries[i];
    Capability cap = nullptr;
    s_app_nodes[i] = nullptr;
    s_app_files[i] = nullptr;
    switch (e.kind) {
      case init::MANIFEST_SYSCALL:
        if (e.count == static_cast<uint32_t>(syscall::Id::compartment_invoke)) {
          cap = s_gate_invoke;
        }
        break;
      case init::MANIFEST_SERVICE:
        cap = program_service(e.name);
        break;
      case init::MANIFEST_DISK:
        cap = grant_disk(prog, e, &s_app_nodes[i]);
        break;
      case init::MANIFEST_FILE:
        if ((e.perms & perms::Load) != 0 &&
            fs_open_with(s_fs_open, s_disk_quota, e.name, &cap, nullptr,
                         e.perms & (perms::Load | perms::Store)) == init::FS_OK) {
          s_app_files[i] = cap;
        } else {
          cap = nullptr;
        }
        break;
      default:
        break;
    }
    s_app_seeds[i] = cap;
    out(" ");
    print_manifest_entry(s_gate_invoke, s_uart, e);
    if (!capability_is_valid(cap)) {
      out((e.flags & init::MANIFEST_REQUIRED) != 0 ? "=REFUSED" : "=none");
      if ((e.flags & init::MANIFEST_REQUIRED) != 0) {
        ok = false;
      }
    }
  }
  out("\n");
  return ok;
}

// Step 6, the grants: nodes destroyed (their directories go with them),
// files closed, slots cleared.
void revoke_manifest(uint32_t count) {
  for (uint32_t i = 0; i < count; ++i) {
    if (capability_is_valid(s_app_files[i])) {
      fs_close(s_app_files[i]);
    }
    if (capability_is_valid(s_app_nodes[i])) {
      const int64_t st = fs_destroy(s_app_nodes[i]);
      if (st != init::FS_OK) {
        fs_fail("run: WARNING: a program's directory would not go", st);
      }
    }
    s_app_files[i] = nullptr;
    s_app_nodes[i] = nullptr;
    s_app_seeds[i] = nullptr;
  }
}

// `loader`: a compartment on `quota` from `image`, seeded with the first
// `count` of `s_app_seeds` (none at all for a manifest with no entries, which
// is what the loader expects then). True with both handles filled in.
bool load_image(Capability quota, uint32_t count, Capability image,
                Capability* out_comp, Capability* out_entry) {
  init::LoadRequest req{};
  req.vm_quota = quota;
  req.seeds = count == 0 ? nullptr
                         : capability_set_bounds(
                               reinterpret_cast<Capability>(&s_app_seeds[0]),
                               static_cast<size_t>(count) * sizeof(Capability));
  req.image = image;
  req.out_comp = nullptr;
  req.out_sentry = nullptr;
  invoke<int64_t>(s_gate_invoke, s_loader, bounded(&req));
  *out_comp = req.out_comp;
  *out_entry = req.out_sentry;
  return sealing::is_sealed_as(OType::Compartment, req.out_comp) &&
         sealing::is_sealed_as(OType::EntryPoint, req.out_sentry);
}

bool cmd_run(const char* name, const char* args, int64_t* out_status) {
  *out_status = RUN_NOT_RUN;
  if (!fs_available()) {
    return false;
  }
  if (!s_run_ready) {
    out("[shell]    run: programs are disabled (see the warning at start)\n");
    return false;
  }
  if (*name == '\0') {
    out("[shell]    usage: run <file> [args]\n");
    return false;
  }
  using FnDealloc = decltype(&sys_vm_deallocate);
  using FnQuotaDerive = decltype(&sys_quota_vm_derive);
  using FnQuotaDestroy = decltype(&sys_quota_vm_destroy);
  using FnCompDestroy = decltype(&sys_compartment_destroy);

  // 1. The file, into memory of the shell's.
  Capability image = read_image("run", name);
  bool ok = capability_is_valid(image);

  // 2. What it asks for, and what it gets.
  init::Manifest manifest{};
  if (ok) {
    const init::CompartmentImageHeader* hdr = init::image_header(image);
    ok = hdr != nullptr && init::manifest_of(image, hdr, &manifest);
    if (!ok) {
      out("[shell]    run: not a program (no header, or a malformed "
          "manifest)\n");
    }
  }
  if (ok) {
    ok = grant_manifest(name, manifest);
    if (!ok) {
      out("[shell]    run: ");
      out(name);
      out(" needs what this shell will not give; not started\n");
    }
  }

  // 3. A quota of its own.
  Capability quota = nullptr;
  if (ok) {
    size_t vm_bytes = manifest.vm_bytes == 0
                          ? APP_VM_DEFAULT
                          : static_cast<size_t>(manifest.vm_bytes);
    if (vm_bytes > APP_VM_MAX) vm_bytes = APP_VM_MAX;
    quota = syscall::call<FnQuotaDerive>(s_gate_invoke, s_gate_q_derive,
                                         s_vm_quota, vm_bytes,
                                         perms::Load | perms::Store);
    ok = sealing::is_sealed_as(OType::QuotaVm, quota);
    if (!ok) {
      out("[shell]    run: no VM quota left for a program\n");
    }
  }

  // 4. The program's compartment. The seeds are all it will ever hold.
  Capability comp = nullptr;
  Capability entry = nullptr;
  if (ok) {
    ok = load_image(quota, manifest.count, image, &comp, &entry);
    if (!ok) {
      out("[shell]    run: not a program (the loader refused the image)\n");
    }
  }

  // 5. Run it, on a thread of its own (THE PROGRAM'S THREAD, above), and
  //    sleep until that thread has ended.
  Capability node = nullptr;
  if (ok) {
    node = derive_app_node();
    ok = capability_is_valid(node);
    if (!ok) {
      out("[shell]    run: no CPU bandwidth left for a program\n");
    }
  }
  if (ok) {
    size_t i = 0;
    for (; i + 1 < init::APP_ARGS_MAX && args[i] != '\0'; ++i) {
      s_app_req.args[i] = args[i];
    }
    for (; i < init::APP_ARGS_MAX; ++i) {
      s_app_req.args[i] = '\0';
    }
    s_app_req.status = RUN_NOT_RUN;
    s_app_req.ticks_per_us = s_ticks_per_us;
    ok = start_app_thread(entry, node);
  }
  if (ok) {
    ok = wait_app_thread(node);
    node = nullptr;  // destroyed by the wait, or left as it would not go
    *out_status = s_app_req.status;
  }
  if (capability_is_valid(node)) {
    destroy_sched_node(node);  // never had a thread on it
  }

  // 6. Take it all down again, in the reverse order it was built.
  if (capability_is_valid(comp)) {
    syscall::call<FnCompDestroy>(s_gate_invoke, s_gate_comp_destroy, comp);
  }
  if (capability_is_valid(quota) &&
      syscall::call<FnQuotaDestroy>(s_gate_invoke, s_gate_q_destroy, quota) !=
          0) {
    out("[shell]    run: WARNING: the program's VM quota would not destroy\n");
  }
  revoke_manifest(manifest.count);
  if (capability_is_valid(image)) {
    syscall::call<FnDealloc>(s_gate_invoke, s_gate_vm_dealloc, s_self_comp,
                             s_vm_quota, image);
  }

  if (ok) {
    out("[shell]    ");
    out(name);
    if (*out_status == RUN_NOT_RUN) {
      out(" returned without a status\n");
    } else if (*out_status < 0) {
      out_dec(" exited with status -", static_cast<uint64_t>(-*out_status),
              "\n");
    } else {
      out_dec(" exited with status ", static_cast<uint64_t>(*out_status),
              "\n");
    }
  }
  return ok;
}

// True if `name` is among the first `count` entries of the last `fs_list`.
bool has_entry(uint64_t count, const char* name) {
  for (uint64_t i = 0; i < count; ++i) {
    if (str_eq(s_entries[i].name, name)) {
      return true;
    }
  }
  return false;
}

// The `owner` mark (FS_OWNER_*) of `name` in the last `fs_list`; ~0u if it is
// not there.
uint32_t entry_owner(uint64_t count, const char* name) {
  for (uint64_t i = 0; i < count; ++i) {
    if (str_eq(s_entries[i].name, name)) {
      return s_entries[i].owner;
    }
  }
  return ~0u;
}

// The program self-test: `hello.bin`, in `/bin`, runs with arguments and
// reports success, which has `run` grant its manifest -- a directory of its
// own under `/home`, the file operations, the message of the day the demo
// writes first -- and take it all back: afterwards `/home/hello` is gone and
// the shell's accounting is what it was. Then each of the shell's two handles
// on the disk denies the program in its own way. Through the `/home` quota
// the file cannot so much as be named -- it is not under that root, and a
// path cannot climb out. Through the read-only `/bin` view it can be opened
// and nothing else: not written, not removed, not joined by anything of the
// shell's.
bool run_app_demo() {
  if (!fs_available() || !s_run_ready) {
    return false;
  }
  bool ok = true;
  auto expect_status = [&](int64_t got, int64_t want, const char* what) {
    if (got != want) {
      ok = false;
      out("[shell]    run demo: FAILED at ");
      out(what);
      out(": got ");
      out(fs_status_name(got));
      out(", wanted ");
      out(fs_status_name(want));
      out("\n");
    }
  };
  // A message of the day for the program's optional FILE entry (a leftover
  // from an interrupted run is replaced), and the shell's accounting with it
  // in place, to compare with afterwards.
  fs_unlink(s_disk_quota, "motd.txt");
  Capability motd = nullptr;
  expect_status(fs_open_with(s_fs_create, s_disk_quota, "motd.txt", &motd),
                init::FS_OK, "create motd.txt");
  if (capability_is_valid(motd)) {
    const char text[] = "be kind to your sandbox\n";
    for (size_t i = 0; i < sizeof(text); ++i) {
      s_data[i] = static_cast<uint8_t>(text[i]);
    }
    uint64_t done = 0;
    expect_status(fs_io(s_fs_write, motd, s_data, 0, sizeof(text) - 1, &done),
                  init::FS_OK, "write motd.txt");
    fs_close(motd);
  }
  init::FsQueryRequest before{};
  expect_status(fs_query(s_disk_quota, before), init::FS_OK, "query before run");

  int64_t status = RUN_NOT_RUN;
  if (!cmd_run("hello.bin", "from the shell's self-test", &status) ||
      status != 0) {
    ok = false;
    out("[shell]    run demo: FAILED at run hello.bin\n");
  }

  // Nothing of the program's outlives it: not its directory, not its charges.
  uint64_t count = 0;
  uint64_t total = 0;
  expect_status(fs_list(s_disk_quota, "", &count, &total), init::FS_OK,
                "ls /home after the run");
  if (has_entry(count, "hello")) {
    ok = false;
    out("[shell]    run demo: FAILED: /home/hello outlived the program\n");
  }
  init::FsQueryRequest after{};
  expect_status(fs_query(s_disk_quota, after), init::FS_OK, "query after run");
  if (after.used_bytes != before.used_bytes ||
      after.used_inodes != before.used_inodes ||
      after.delegated_bytes != before.delegated_bytes ||
      after.delegated_inodes != before.delegated_inodes) {
    ok = false;
    out("[shell]    run demo: FAILED: the shell's accounting changed\n");
    print_quota("[shell]    before: ", before);
    print_quota("[shell]    after:  ", after);
  }
  expect_status(fs_unlink(s_disk_quota, "motd.txt"), init::FS_OK, "rm motd.txt");

  Capability file = nullptr;
  // Not under /home, and no way to say "up one".
  expect_status(fs_open_with(s_fs_open, s_disk_quota, "hello.bin", &file),
                init::FS_NOT_FOUND, "open hello.bin through /home");
  expect_status(fs_unlink(s_disk_quota, "hello.bin"), init::FS_NOT_FOUND,
                "rm hello.bin through /home");
  expect_status(fs_open_with(s_fs_open, s_disk_quota, "../bin/hello.bin", &file),
                init::FS_BAD_REQUEST, "open ../bin/hello.bin through /home");
  // Under /bin, through a handle that only reads.
  expect_status(fs_unlink(s_bin_quota, "hello.bin"), init::FS_PERMISSION,
                "rm hello.bin through /bin");
  expect_status(fs_open_with(s_fs_create, s_bin_quota, "mine.bin", &file),
                init::FS_PERMISSION, "create mine.bin in /bin");
  expect_status(fs_mkdir(s_bin_quota, "mine"), init::FS_PERMISSION,
                "mkdir mine in /bin");
  expect_status(fs_open_with(s_fs_open, s_bin_quota, "hello.bin", &file),
                init::FS_OK, "open hello.bin through /bin");
  if (capability_is_valid(file)) {
    uint64_t done = 0;
    s_data[0] = 0;
    expect_status(fs_io(s_fs_write, file, s_data, 0, 1, &done),
                  init::FS_PERMISSION, "write hello.bin through /bin");
    fs_close(file);
  }
  out(ok ? "[shell]    run demo OK\n" : "[shell]    run demo FAILED\n");
  return ok;
}

// The file-system self-test: a file written and read back; a directory, and a
// sub-quota rooted at it that runs out of bytes and then of inodes, cannot
// reach above its directory, and can see but not touch what the shell put in
// it; its node's page full of open files; the cascade when the sub-quota is
// destroyed and the handle that dies with it; adoption, down two levels; what
// keeps a directory from being removed; the shell's own accounting restored
// at the end. Idempotent: leftovers from an interrupted run are removed first
// -- and they are the shell's to remove even after a reboot, since `init`
// derives its node with FS_DERIVE_ADOPT.
bool run_fs_demo() {
  if (!fs_available()) {
    return false;
  }
  bool ok = true;
  auto expect = [&](bool cond, const char* what) {
    if (!cond) {
      ok = false;
      out("[shell]    fs demo: FAILED at ");
      out(what);
      out("\n");
    }
  };
  auto expect_status = [&](int64_t got, int64_t want, const char* what) {
    if (got != want) {
      ok = false;
      out("[shell]    fs demo: FAILED at ");
      out(what);
      out(": got ");
      out(fs_status_name(got));
      out(", wanted ");
      out(fs_status_name(want));
      out("\n");
    }
  };
  static const char kText[] = "Hello from SignetOS!\n";
  const uint64_t kTextLen = sizeof(kText) - 1;

  out("[shell]    fs demo: starting\n");
  fs_unlink(s_disk_quota, "hello.txt");
  fs_unlink(s_disk_quota, "big.bin");
  fs_unlink(s_disk_quota, "sandbox/sub_a");
  fs_unlink(s_disk_quota, "sandbox/sub_b");
  fs_unlink(s_disk_quota, "sandbox/readme");
  fs_unlink(s_disk_quota, "sandbox");

  init::FsQueryRequest q{};
  expect_status(fs_query(s_disk_quota, q), init::FS_OK, "query");
  print_quota("[shell]    fs demo: before: ", q);
  const uint64_t base_used = q.used_bytes;
  const uint32_t base_inodes = q.used_inodes;
  // Whatever else is in /home stays there throughout, so the entry counts
  // below are relative to it.
  uint64_t count = 0;
  uint64_t total = 0;
  expect_status(fs_list(s_disk_quota, "", &count, &total), init::FS_OK,
                "list at the start");
  const uint64_t base_total = total;

  // 1. A file: create, write, read back.
  Capability file = nullptr;
  expect_status(fs_open_with(s_fs_create, s_disk_quota, "hello.txt", &file),
                init::FS_OK, "create hello.txt");
  for (uint64_t i = 0; i < kTextLen; ++i) {
    s_data[i] = static_cast<uint8_t>(kText[i]);
  }
  uint64_t done = 0;
  expect_status(fs_io(s_fs_write, file, s_data, 0, kTextLen, &done),
                init::FS_OK, "write hello.txt");
  expect(done == kTextLen, "write hello.txt count");
  expect_status(fs_close(file), init::FS_OK, "close hello.txt");
  expect_status(fs_open_with(s_fs_open, s_disk_quota, "hello.txt", &file),
                init::FS_OK, "open hello.txt");
  for (uint64_t i = 0; i < kTextLen; ++i) {
    s_data[i] = 0;
  }
  expect_status(fs_io(s_fs_read, file, s_data, 0, DATA_MAX, &done),
                init::FS_OK, "read hello.txt");
  bool same = done == kTextLen;
  for (uint64_t i = 0; same && i < kTextLen; ++i) {
    same = s_data[i] == static_cast<uint8_t>(kText[i]);
  }
  expect(same, "read hello.txt contents");
  expect_status(fs_close(file), init::FS_OK, "close hello.txt again");
  expect_status(fs_query(s_disk_quota, q), init::FS_OK, "query after write");
  expect(q.used_bytes == base_used + init::FS_BLOCK_BYTES &&
             q.used_inodes == base_inodes + 1,
         "one block and one inode charged for hello.txt");

  // 2. A directory of the shell's with a file of the shell's in it, and a
  //    sub-quota of 8 KiB and 2 inodes rooted at the directory. The paths the
  //    sub-quota uses start there.
  expect_status(fs_mkdir(s_disk_quota, "sandbox"), init::FS_OK, "mkdir sandbox");
  expect_status(fs_mkdir(s_disk_quota, "sandbox"), init::FS_EXISTS,
                "mkdir sandbox again");
  expect_status(fs_open_with(s_fs_create, s_disk_quota, "sandbox/readme", &file),
                init::FS_OK, "create sandbox/readme");
  expect_status(fs_close(file), init::FS_OK, "close sandbox/readme");
  expect_status(fs_query(s_disk_quota, q), init::FS_OK, "query with sandbox");
  expect(q.used_inodes == base_inodes + 3,
         "an inode each for hello.txt, sandbox and sandbox/readme");
  Capability sub = nullptr;
  expect_status(fs_derive(s_disk_quota, "hello.txt", 0, 0, &sub),
                init::FS_NOT_DIR, "derive at a file");
  expect_status(fs_derive(s_disk_quota, "nowhere", 0, 0, &sub),
                init::FS_NOT_FOUND, "derive at a missing directory");
  expect_status(
      fs_derive(s_disk_quota, "sandbox", 2 * init::FS_BLOCK_BYTES, 2, &sub),
      init::FS_OK, "derive sub-quota at sandbox");
  Capability file_a = nullptr;
  expect_status(fs_open_with(s_fs_create, sub, "sub_a", &file_a), init::FS_OK,
                "create sub_a");
  for (size_t i = 0; i < DATA_MAX; ++i) {
    s_data[i] = static_cast<uint8_t>(i);
  }
  expect_status(fs_io(s_fs_write, file_a, s_data, 0, DATA_MAX, &done),
                init::FS_OK, "write 8 KiB to sub_a");
  expect_status(fs_io(s_fs_write, file_a, s_data, DATA_MAX, 1, &done),
                init::FS_QUOTA, "write past the sub-quota's bytes");
  expect_status(fs_close(file_a), init::FS_OK, "close sub_a");
  Capability file_b = nullptr;
  expect_status(fs_open_with(s_fs_create, sub, "sub_b", &file_b), init::FS_OK,
                "create sub_b");
  expect_status(fs_close(file_b), init::FS_OK, "close sub_b");
  Capability file_c = nullptr;
  expect_status(fs_open_with(s_fs_create, sub, "sub_c", &file_c),
                init::FS_QUOTA, "create past the sub-quota's inodes");
  expect_status(fs_mkdir(sub, "nested"), init::FS_QUOTA,
                "mkdir past the sub-quota's inodes");
  // Nothing above its directory can be named, by any spelling.
  expect_status(fs_open_with(s_fs_open, sub, "hello.txt", &file),
                init::FS_NOT_FOUND, "open hello.txt through the sub-quota");
  expect_status(fs_unlink(sub, "hello.txt"), init::FS_NOT_FOUND,
                "unlink hello.txt through the sub-quota");
  expect_status(fs_open_with(s_fs_open, sub, "../hello.txt", &file),
                init::FS_BAD_REQUEST, "open ../hello.txt through the sub-quota");
  expect_status(fs_open_with(s_fs_open, sub, "/sandbox/readme", &file),
                init::FS_BAD_REQUEST, "open an absolute path through the sub-quota");
  // The shell's file in its directory: there to read, not its to change.
  expect_status(fs_open_with(s_fs_open, sub, "readme", &file), init::FS_OK,
                "open readme through the sub-quota");
  expect_status(fs_io(s_fs_write, file, s_data, 0, 1, &done),
                init::FS_PERMISSION, "write readme through the sub-quota");
  expect_status(fs_close(file), init::FS_OK, "close readme");
  expect_status(fs_unlink(sub, "readme"), init::FS_PERMISSION,
                "unlink readme through the sub-quota");
  // Open files are the opener's own: the sub-quota's node has room for
  // FS_OPEN_PER_NODE handles and not one more, and filling it leaves the
  // shell's node as free to open as before.
  size_t opened = 0;
  while (opened < init::FS_OPEN_PER_NODE &&
         fs_open_with(s_fs_open, sub, "readme", &s_handles[opened]) ==
             init::FS_OK) {
    opened += 1;
  }
  expect(opened == init::FS_OPEN_PER_NODE,
         "open readme FS_OPEN_PER_NODE times through the sub-quota");
  expect_status(fs_open_with(s_fs_open, sub, "readme", &file),
                init::FS_NO_MEMORY, "open past the sub-quota's node page");
  expect_status(fs_open_with(s_fs_open, s_disk_quota, "hello.txt", &file),
                init::FS_OK, "open hello.txt while the sub-quota's page is full");
  expect_status(fs_close(file), init::FS_OK, "close that hello.txt");
  for (size_t i = 0; i < opened; ++i) {
    fs_close(s_handles[i]);
  }
  // One handle opened through the sub-quota, kept to outlive it (below).
  Capability orphan = nullptr;
  expect_status(fs_open_with(s_fs_open, sub, "readme", &orphan), init::FS_OK,
                "open readme through the sub-quota once more");
  init::FsQueryRequest qs{};
  expect_status(fs_query(sub, qs), init::FS_OK, "query sub-quota");
  print_quota("[shell]    fs demo: sub-quota: ", qs);
  expect(qs.used_bytes == 2 * init::FS_BLOCK_BYTES && qs.used_inodes == 2 &&
             qs.limit_bytes == 2 * init::FS_BLOCK_BYTES && qs.limit_inodes == 2,
         "sub-quota accounting");
  expect_status(fs_query(s_disk_quota, q), init::FS_OK, "query with sub-quota");
  expect(q.delegated_bytes == 2 * init::FS_BLOCK_BYTES && q.delegated_inodes == 2,
         "delegation charged to the shell's quota");
  // Listings: the same directory from both sides, each side's ownership
  // marks from its own point of view.
  expect_status(fs_list(s_disk_quota, "", &count, &total), init::FS_OK, "list");
  expect(total == base_total + 2 && has_entry(count, "hello.txt") &&
             has_entry(count, "sandbox"),
         "list sees hello.txt and sandbox");
  expect_status(fs_list(s_disk_quota, "sandbox", &count, &total), init::FS_OK,
                "list sandbox");
  expect(total == 3 && has_entry(count, "readme") && has_entry(count, "sub_a") &&
             has_entry(count, "sub_b"),
         "list sandbox sees readme, sub_a and sub_b");
  expect(entry_owner(count, "readme") == init::FS_OWNER_SELF &&
             entry_owner(count, "sub_a") == init::FS_OWNER_CHILD,
         "the shell owns readme; sub_a belongs to its sub-quota");
  expect_status(fs_list(sub, "", &count, &total), init::FS_OK,
                "list through the sub-quota");
  expect(total == 3 && entry_owner(count, "readme") == init::FS_OWNER_OTHER &&
             entry_owner(count, "sub_a") == init::FS_OWNER_SELF,
         "to the sub-quota readme is another's and sub_a its own");
  expect_status(fs_list(s_disk_quota, "hello.txt", &count, &total),
                init::FS_NOT_DIR, "list a file");
  expect_status(fs_unlink(s_disk_quota, "sandbox"), init::FS_NOT_EMPTY,
                "rm sandbox while it has entries");

  // 3. Destroying the sub-quota takes its files with it and refunds the
  //    shell; the shell's own file in the directory stays. A handle opened
  //    through the sub-quota went with its page.
  expect_status(fs_destroy(sub), init::FS_OK, "destroy sub-quota");
  expect_status(fs_io(s_fs_read, orphan, s_data, 0, 1, &done),
                init::FS_INVALID_FILE, "read through a handle whose node is gone");
  expect_status(fs_list(s_disk_quota, "sandbox", &count, &total), init::FS_OK,
                "list sandbox after destroy");
  expect(total == 1 && has_entry(count, "readme") && !has_entry(count, "sub_a") &&
             !has_entry(count, "sub_b"),
         "only readme is left in sandbox");
  expect_status(fs_query(s_disk_quota, q), init::FS_OK, "query after destroy");
  expect(q.delegated_bytes == 0 && q.delegated_inodes == 0,
         "delegation returned to the shell's quota");
  // Adoption: a node derived with FS_DERIVE_ADOPT starts out owning what its
  // parent owned at or under its root -- here `sandbox` itself and `readme`,
  // two inodes -- charged to it from then on, and takes them with it when it
  // is destroyed. With no room for them, nothing is made.
  expect_status(fs_derive(s_disk_quota, "sandbox", 0, 1, &sub,
                          perms::Load | perms::Store, nullptr,
                          init::FS_DERIVE_ADOPT),
                init::FS_QUOTA, "adopt two inodes into a node allowed one");
  expect_status(fs_derive(s_disk_quota, "sandbox", 0, 2, &sub,
                          perms::Load | perms::Store, nullptr,
                          init::FS_DERIVE_ADOPT),
                init::FS_OK, "derive a node adopting sandbox and readme");
  expect_status(fs_query(sub, qs), init::FS_OK, "query the adopting node");
  expect(qs.used_inodes == 2 && qs.used_bytes == 0,
         "sandbox and readme charged to the adopting node");
  expect_status(fs_query(s_disk_quota, q), init::FS_OK, "query after adoption");
  expect(q.used_inodes == base_inodes + 1,
         "only hello.txt still charged to the shell");
  expect_status(fs_list(s_disk_quota, "", &count, &total), init::FS_OK,
                "list after adoption");
  expect(entry_owner(count, "sandbox") == init::FS_OWNER_CHILD,
         "sandbox now belongs to the adopting node");
  // A node with nothing left to give can still hand down, whole, what it
  // has: an inner node adopts the same two inodes from a node that spent both
  // of its own on them. Destroying the inner node unlinks readme; sandbox,
  // which the outer node is rooted at, passes back to it rather than going --
  // no node is pinned by another being rooted in a directory of its.
  Capability inner = nullptr;
  expect_status(fs_derive(sub, "", 0, 2, &inner, perms::Load | perms::Store,
                          nullptr, init::FS_DERIVE_ADOPT),
                init::FS_OK, "hand sandbox down whole from a node with nothing spare");
  expect_status(fs_query(inner, qs), init::FS_OK, "query the inner node");
  expect(qs.used_inodes == 2 && qs.limit_inodes == 2,
         "sandbox and readme charged to the inner node");
  expect_status(fs_query(sub, qs), init::FS_OK, "query the outer node");
  expect(qs.used_inodes == 0 && qs.delegated_inodes == 2,
         "the outer node has passed both inodes on");
  expect_status(fs_destroy(sub), init::FS_BUSY, "destroy the outer node first");
  expect_status(fs_destroy(inner), init::FS_OK, "destroy the inner node");
  expect_status(fs_query(sub, qs), init::FS_OK, "query the outer node after");
  expect(qs.used_inodes == 1 && qs.delegated_inodes == 0,
         "readme went with the inner node; sandbox came back to the outer");
  expect_status(fs_destroy(sub), init::FS_OK, "destroy the adopting node");
  expect_status(fs_list(s_disk_quota, "", &count, &total), init::FS_OK,
                "list after the adopting node is gone");
  expect(total == base_total + 1 && !has_entry(count, "sandbox"),
         "sandbox went with the node that adopted it");
  expect_status(fs_query(s_disk_quota, q), init::FS_OK,
                "query after the adopting node is gone");
  expect(q.used_inodes == base_inodes + 1 && q.delegated_inodes == 0,
         "nothing of sandbox's is charged anywhere");
  // A node rooted at a directory keeps it, even an empty one. A read-only
  // node cannot be destroyed through the handle its holder gets; its creator
  // destroys it through the ADMIN handle derive hands back alongside.
  expect_status(fs_mkdir(s_disk_quota, "sandbox"), init::FS_OK,
                "mkdir sandbox once more");
  Capability viewer = nullptr;
  Capability viewer_admin = nullptr;
  expect_status(fs_derive(s_disk_quota, "sandbox", 0, 0, &viewer, perms::Load,
                          &viewer_admin),
                init::FS_OK, "derive a read-only node at sandbox");
  expect_status(fs_open_with(s_fs_create, viewer, "x", &file),
                init::FS_PERMISSION, "create through a read-only node");
  expect_status(fs_unlink(s_disk_quota, "sandbox"), init::FS_BUSY,
                "rm sandbox while a node is rooted at it");
  expect_status(fs_destroy(viewer), init::FS_PERMISSION,
                "destroy a node through its read-only handle");
  expect_status(fs_destroy(viewer_admin), init::FS_OK,
                "destroy it through its ADMIN handle");
  expect_status(fs_unlink(s_disk_quota, "sandbox"), init::FS_OK, "rm sandbox");

  // 4. Still there after all that; then gone.
  expect_status(fs_open_with(s_fs_open, s_disk_quota, "hello.txt", &file),
                init::FS_OK, "reopen hello.txt");
  expect_status(fs_io(s_fs_read, file, s_data, 0, DATA_MAX, &done), init::FS_OK,
                "reread hello.txt");
  same = done == kTextLen;
  for (uint64_t i = 0; same && i < kTextLen; ++i) {
    same = s_data[i] == static_cast<uint8_t>(kText[i]);
  }
  expect(same, "reread hello.txt contents");
  expect_status(fs_close(file), init::FS_OK, "close hello.txt finally");
  expect_status(fs_io(s_fs_read, file, s_data, 0, 1, &done),
                init::FS_INVALID_FILE, "read through a closed handle");
  expect_status(fs_unlink(s_disk_quota, "hello.txt"), init::FS_OK,
                "unlink hello.txt");
  expect_status(fs_list(s_disk_quota, "", &count, &total), init::FS_OK,
                "list at the end");
  expect(total == base_total && !has_entry(count, "hello.txt") &&
             !has_entry(count, "sandbox"),
         "nothing of the demo's left");
  expect_status(fs_query(s_disk_quota, q), init::FS_OK, "query at the end");
  expect(q.used_bytes == base_used && q.used_inodes == base_inodes,
         "the shell's quota is back where it started");

  // 5. A file larger than the 16 direct blocks (> 64 KiB): crosses into the
  //    single-indirect block (17 data blocks + 1 indirect block = 18 blocks).
  fs_unlink(s_disk_quota, "big.bin");
  expect_status(fs_open_with(s_fs_create, s_disk_quota, "big.bin", &file),
                init::FS_OK, "create big.bin");
  for (size_t i = 0; i < DATA_MAX; ++i) {
    s_data[i] = static_cast<uint8_t>((i * 7u) ^ 0x5au);
  }
  const uint64_t big_off = init::FS_DIRECT_BLOCKS * init::FS_BLOCK_BYTES;
  expect_status(fs_io(s_fs_write, file, s_data, big_off, init::FS_BLOCK_BYTES,
                      &done),
                init::FS_OK, "write 17th block of big.bin (indirect)");
  expect(done == init::FS_BLOCK_BYTES, "write 17th block count");
  expect_status(fs_close(file), init::FS_OK, "close big.bin");
  expect_status(fs_query(s_disk_quota, q), init::FS_OK, "query with big.bin");
  expect(q.used_bytes ==
             base_used + (init::FS_DIRECT_BLOCKS + 2) * init::FS_BLOCK_BYTES,
         "17 data blocks + 1 indirect block charged for big.bin");
  expect_status(fs_open_with(s_fs_open, s_disk_quota, "big.bin", &file),
                init::FS_OK, "reopen big.bin");
  for (size_t i = 0; i < init::FS_BLOCK_BYTES; ++i) {
    s_data[i] = 0;
  }
  expect_status(fs_io(s_fs_read, file, s_data, big_off, init::FS_BLOCK_BYTES,
                      &done),
                init::FS_OK, "read 17th block of big.bin");
  bool big_ok = done == init::FS_BLOCK_BYTES;
  for (size_t i = 0; big_ok && i < init::FS_BLOCK_BYTES; ++i) {
    big_ok = s_data[i] == static_cast<uint8_t>((i * 7u) ^ 0x5au);
  }
  expect(big_ok, "read 17th block contents");
  expect_status(fs_close(file), init::FS_OK, "close big.bin again");
  expect_status(fs_unlink(s_disk_quota, "big.bin"), init::FS_OK,
                "unlink big.bin");
  expect_status(fs_query(s_disk_quota, q), init::FS_OK, "query after big.bin");
  expect(q.used_bytes == base_used && q.used_inodes == base_inodes,
         "indirect + data blocks refunded after unlink");
  print_quota("[shell]    fs demo: after: ", q);

  out(ok ? "[shell]    fs demo OK\n" : "[shell]    fs demo FAILED\n");
  return ok;
}

void print_help() {
  out("  help       this text\n"
      "  stats      CPU time the background workers have received\n"
      "  demo       300 ms bandwidth self-test (5:3:1 workers + a batch hog)\n"
      "  fsdemo     file system self-test (directories, sub-quotas, cascade)\n"
      "  ls [dir]   list a directory (paths are under /home, the shell's root)\n"
      "  cat <f>    print a file\n"
      "  write <f> <text>   replace a file with a line of text\n"
      "  append <f> <text>  add a line of text to a file\n"
      "  mkdir <d>  make a directory\n"
      "  rm <p>     remove a file or an empty directory\n"
      "  df         the shell's disk quota: used, delegated, limit\n"
      "  run <f> [args]     load a program from /bin into a compartment "
      "of its own and run it\n"
      "  shutdown   stop the workers and power the machine off\n");
}

// killtest: a temporary check of thread kill, not part of the shell.
// `killtest spin|sleep|fs|stuck` starts a thread whose own code
// is the shell, lets it run for 100 ms, kills it with `sched.thread_kill`, and
// says how long it took to go. What the thread is doing when the kill lands:
//   spin      running its own code
//   sleep     asleep in `sched.block` with nobody to wake it
//   fs        reading a file: inside fs, and blk, most of the time
//   stuck     inside a call to the shell that never returns
uint64_t s_killtest_mode = 0;
Capability s_killtest_stuck = nullptr;
alignas(16) char s_killtest_buf[4096];

// Never returns. Reached through a sentry, so a thread in here is inside a
// call to the shell -- which is not trusted to finish.
uint64_t killtest_stuck() {
  for (;;) {
    __asm__ volatile("" ::: "memory");
  }
}

uint64_t killtest_thread(Capability) {
  Capability file = nullptr;
  if (s_killtest_mode == 2) {
    fs_open_with(s_fs_open, s_bin_quota, "logo.bin", &file, nullptr, perms::Load);
  }
  for (;;) {
    if (s_killtest_mode == 1) {
      invoke<int64_t>(s_gate_invoke, s_sched_block, 0ULL);
    } else if (s_killtest_mode == 2) {
      uint64_t got = 0;
      fs_io(s_fs_read, file, s_killtest_buf, 0, sizeof(s_killtest_buf), &got);
    } else if (s_killtest_mode == 3) {
      invoke<int64_t>(s_gate_invoke, s_killtest_stuck);
    }
  }
}

void cmd_killtest(const char* mode) {
  const char* modes[] = {"spin", "sleep", "fs", "stuck"};
  s_killtest_mode = 4;
  for (uint64_t i = 0; i < 4; ++i) {
    if (str_eq(mode, modes[i])) {
      s_killtest_mode = i;
    }
  }
  if (s_killtest_mode == 4) {
    out("[killtest] usage: killtest spin|sleep|fs|stuck\n");
    return;
  }
  Capability* rw = rw_table();
  auto mint = [&](const void* fn) {
    return mint_entry(s_gate_invoke, rw[SLOT_SYS_SENTRY], s_self_comp, fn);
  };
  s_killtest_stuck = mint(reinterpret_cast<const void*>(&killtest_stuck));
  const Capability entry = mint(reinterpret_cast<const void*>(&killtest_thread));
  const Capability kill =
      lookup_name(s_gate_invoke, rw[SLOT_NAMING_LOOKUP], "sched.thread_kill");
  const Capability node = derive_app_node();
  using FnThreadCreate = decltype(&sys_thread_create);
  const Capability t = syscall::call<FnThreadCreate>(
      s_gate_invoke, s_gate_thread_create, s_thread_quota, APP_STACK, entry,
      nullptr);
  if (!capability_is_valid(kill) || !capability_is_valid(node) ||
      !sealing::is_sealed_as(OType::Thread, t) ||
      invoke<int64_t>(s_gate_invoke, s_sched_register, t, node) <= 0) {
    out("[killtest] could not start the test thread\n");
    return;
  }
  sleep_us(100'000);
  const uint64_t t0 = now_us();
  const int64_t st = invoke<int64_t>(s_gate_invoke, kill, t);
  out_dec("[killtest] sched.thread_kill: status -", static_cast<uint64_t>(-st),
          "\n");
  while (destroy_sched_node(node) == init::SCHED_BUSY) {
    if (now_us() - t0 > 2'000'000) {
      out("[killtest] the thread is still there 2 s after the kill\n");
      return;
    }
    sleep_us(1'000);
  }
  out_dec("[killtest] the thread was gone ", (now_us() - t0) / 1000,
          " ms after the kill\n");
}

// Runs one command line (edited in place to split off arguments). False means
// the console should end.
bool execute(char* line) {
  char* rest = nullptr;
  const char* cmd = first_word(line, &rest);
  if (str_eq(cmd, "help")) {
    print_help();
  } else if (str_eq(cmd, "stats")) {
    print_stats();
  } else if (str_eq(cmd, "demo")) {
    run_demo();
  } else if (str_eq(cmd, "fsdemo")) {
    run_fs_demo();
  } else if (str_eq(cmd, "ls")) {
    cmd_ls(rest);
  } else if (str_eq(cmd, "cat")) {
    cmd_cat(rest);
  } else if (str_eq(cmd, "write") || str_eq(cmd, "append")) {
    char* text = nullptr;
    const char* name = first_word(rest, &text);
    cmd_write(name, text, str_eq(cmd, "append"));
  } else if (str_eq(cmd, "mkdir")) {
    cmd_mkdir(rest);
  } else if (str_eq(cmd, "rm")) {
    cmd_rm(rest);
  } else if (str_eq(cmd, "df")) {
    cmd_df();
  } else if (str_eq(cmd, "run")) {
    char* args = nullptr;
    const char* name = first_word(rest, &args);
    int64_t status = RUN_NOT_RUN;
    cmd_run(name, args, &status);
  } else if (str_eq(cmd, "killtest")) {
    cmd_killtest(rest);
  } else if (str_eq(cmd, "shutdown")) {
    return false;
  } else {
    out("[shell]    unknown command: ");
    out(cmd);
    out(" (try 'help')\n");
  }
  return true;
}

// --- Console -----------------------------------------------------------------

// Whatever has been typed since the last call; 0 if nothing. Every call also
// tells `uart` whom to wake when the next byte arrives: a byte that lands
// between this returning 0 and the `block()` below still ends up as a wake the
// scheduler holds for us.
size_t read_input(char* buf, size_t max) {
  Capability b = capability_set_bounds(reinterpret_cast<Capability>(buf), max);
  return static_cast<size_t>(
      invoke<uint64_t>(s_gate_invoke, s_uart_read, b, s_notify_entry));
}

void echo(char c) {
  const char s[2] = {c, '\0'};
  out(s);
}

// Line editing is Enter and Backspace; the terminal is in raw mode under
// QEMU, so Enter arrives as '\r'. Returns when `shutdown` is entered.
void console_loop() {
  char line[LINE_MAX];
  size_t len = 0;
  out("SignetOS> ");
  for (;;) {
    char in[16];
    const size_t n = read_input(in, sizeof(in));
    if (n == 0) {
      block();  // sleep until the UART interrupt says a key was pressed
      continue;
    }
    for (size_t i = 0; i < n; ++i) {
      const char c = in[i];
      if (c == '\r' || c == '\n') {
        out("\n");
        line[len] = '\0';
        if (len > 0 && !execute(line)) {
          return;
        }
        len = 0;
        out("SignetOS> ");
      } else if (c == 0x7f || c == 0x08) {  // DEL or BS
        if (len > 0) {
          len -= 1;
          out("\b \b");
        }
      } else if (c >= 0x20 && c < 0x7f && len + 1 < LINE_MAX) {
        line[len++] = c;
        echo(c);
      }
    }
  }
}

}  // namespace

// A worker: fixed slices of work until told to stop or the deadline passes.
// Interactive workers yield after each slice; a batch worker never does, so it
// is only ever displaced by the scheduler's tick handler (preemption).
extern "C" uint64_t shell_worker_entry(Capability arg) {
  if (!capability_is_valid(arg) ||
      capability_get_length(arg) < sizeof(WorkerArg)) {
    return 0;
  }
  auto* wa = reinterpret_cast<WorkerArg*>(arg);
  Shared* sh = wa->shared;
  const bool greedy = sh->greedy[wa->index];
  // A fixed slice of work per iteration, so the count measures CPU time
  // received and not how cheap a yield happened to be.
  while (__atomic_load_n(&sh->stop, __ATOMIC_SEQ_CST) == 0 &&
         now_us() < sh->deadline_us) {
    const uint64_t until = now_us() + sh->slice_us;
    while (now_us() < until) {
      __asm__ volatile("" ::: "memory");
    }
    sh->count[wa->index] += 1;
    if (!greedy) {
      invoke<int64_t>(sh->invoke, sh->yield);
    }
  }
  __atomic_fetch_add(&sh->done, 1, __ATOMIC_SEQ_CST);
  // Returning exits the thread; the scheduler unregisters it.
  return 0;
}

// Invoked by `uart` from interrupt context when input arrives and the shell
// asked to be told (see `read_input`). Runs masked, on whichever thread was
// interrupted -- possibly the shell's own, asleep in `sched.block` -- so it
// does the one thing it is for and returns: wake the shell thread.
extern "C" int64_t shell_notify_entry() {
  return invoke<int64_t>(s_gate_invoke, s_sched_wake, s_my_tid);
}

// TODO: This is hacky (multiplexing one-time init/banner vs scheduled thread
// entry by checking if `arg` is sealed as QuotaSched). Let's make this be
// nicer.
extern "C" int64_t compartment_main(Capability arg) {
  Capability* rw = rw_table();

  Capability self_comp = rw[compartment::SLOT_SELF];
  Capability vm_quota = rw[compartment::SLOT_VM_QUOTA];

  // The manifest's slots (SHELL_MANIFEST above): entry i is slot SEED_BASE + i.
  Capability thread_quota = rw[SLOT_THREAD_QUOTA];
  Capability gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  Capability gate_thread_create = rw[SLOT_SYS_THREAD_CREATE];
  Capability gate_sentry = rw[SLOT_SYS_SENTRY];
  Capability uart_sentry = rw[SLOT_UART_SENTRY];
  Capability naming_lookup = rw[SLOT_NAMING_LOOKUP];
  Capability loader_sentry = rw[SLOT_LOADER_SENTRY];
  Capability uart_read = rw[SLOT_UART_READ];
  // For `run`: memory for the image, a sub-quota for the program's
  // compartment, and the means to take the compartment down again.
  Capability gate_vm_alloc = rw[SLOT_SYS_VM_ALLOC];
  Capability gate_vm_dealloc = rw[SLOT_SYS_VM_DEALLOC];
  Capability gate_q_derive = rw[SLOT_SYS_QUOTA_VM_DERIVE];
  Capability gate_q_destroy = rw[SLOT_SYS_QUOTA_VM_DESTROY];
  Capability gate_comp_destroy = rw[SLOT_SYS_COMP_DESTROY];

  if (!sealing::is_sealed_as(OType::Compartment, self_comp) ||
      !sealing::is_sealed_as(OType::QuotaVm, vm_quota) ||
      !sealing::is_sealed_as(OType::QuotaThreadMem, thread_quota) ||
      !sealing::is_sealed_as(OType::EntryPoint, uart_sentry) ||
      !sealing::is_sealed_as(OType::EntryPoint, naming_lookup) ||
      !sealing::is_sealed_as(OType::EntryPoint, loader_sentry)) {
    return -1;
  }

  if (!sealing::is_sealed_as(OType::QuotaSched, arg)) {
    if (capability_is_valid(arg)) {
      const uint64_t hz = *reinterpret_cast<const uint64_t*>(arg);
      if (hz >= 1'000'000) {
        s_ticks_per_us = hz / 1'000'000;
      }
    }
    banner(gate_invoke, uart_sentry, naming_lookup);
    return 0;
  }

  // ---- The shell's scheduled thread ----------------------------------------
  s_gate_invoke = gate_invoke;
  s_gate_thread_create = gate_thread_create;
  s_uart = uart_sentry;
  s_uart_read = uart_read;
  s_vm_quota = vm_quota;
  s_thread_quota = thread_quota;
  s_my_quota = arg;

  s_sched_derive =
      lookup_name(gate_invoke, naming_lookup, "sched.quota_derive");
  s_sched_destroy =
      lookup_name(gate_invoke, naming_lookup, "sched.quota_destroy");
  s_sched_register =
      lookup_name(gate_invoke, naming_lookup, "sched.thread_register");
  s_sched_yield = lookup_name(gate_invoke, naming_lookup, "sched.yield");
  s_sched_block = lookup_name(gate_invoke, naming_lookup, "sched.block");
  s_sched_wake = lookup_name(gate_invoke, naming_lookup, "sched.wake");
  Capability sched_self = lookup_name(gate_invoke, naming_lookup, "sched.self");
  if (!capability_is_valid(s_sched_derive) ||
      !capability_is_valid(s_sched_destroy) ||
      !capability_is_valid(s_sched_register) ||
      !capability_is_valid(s_sched_yield) ||
      !capability_is_valid(s_sched_block) ||
      !capability_is_valid(s_sched_wake) || !capability_is_valid(sched_self)) {
    out("[shell]    sched.* lookup FAILED\n");
    return -1;
  }
  out("[shell]    Running on the scheduler; sched.* resolved by name\n");

  // The file system: its entry points by name, and the two handles the
  // manifest asked for -- the shell's quota at `/home` and the read-only view
  // of `/bin`. Anything missing just turns the file commands off.
  s_disk_quota = rw[SLOT_DISK_QUOTA];
  s_bin_quota = rw[SLOT_BIN_DIR];
  s_fs_derive = lookup_name(gate_invoke, naming_lookup, "fs.quota_derive");
  s_fs_destroy = lookup_name(gate_invoke, naming_lookup, "fs.quota_destroy");
  s_fs_query = lookup_name(gate_invoke, naming_lookup, "fs.quota_query");
  s_fs_create = lookup_name(gate_invoke, naming_lookup, "fs.create");
  s_fs_mkdir = lookup_name(gate_invoke, naming_lookup, "fs.mkdir");
  s_fs_open = lookup_name(gate_invoke, naming_lookup, "fs.open");
  s_fs_close = lookup_name(gate_invoke, naming_lookup, "fs.close");
  s_fs_read = lookup_name(gate_invoke, naming_lookup, "fs.read");
  s_fs_write = lookup_name(gate_invoke, naming_lookup, "fs.write");
  s_fs_unlink = lookup_name(gate_invoke, naming_lookup, "fs.unlink");
  s_fs_list = lookup_name(gate_invoke, naming_lookup, "fs.list");
  s_fs_ready =
      sealing::is_sealed_as(OType::QuotaDisk, s_disk_quota) &&
      capability_is_valid(s_fs_derive) && capability_is_valid(s_fs_destroy) &&
      capability_is_valid(s_fs_query) && capability_is_valid(s_fs_create) &&
      capability_is_valid(s_fs_mkdir) && capability_is_valid(s_fs_open) &&
      capability_is_valid(s_fs_close) && capability_is_valid(s_fs_read) &&
      capability_is_valid(s_fs_write) && capability_is_valid(s_fs_unlink) &&
      capability_is_valid(s_fs_list);
  out(s_fs_ready
          ? "[shell]    fs.* resolved by name; quota at /home received\n"
          : "[shell]    WARNING: no file system (fs.* or the /home quota is "
            "missing); file commands disabled\n");

  // Programs: `run` needs the file system above, the view of `/bin`, and all
  // of these. The manifest asks `init` for every one; a system that will not
  // give them just loses the command.
  s_self_comp = self_comp;
  s_loader = loader_sentry;
  s_gate_vm_alloc = gate_vm_alloc;
  s_gate_vm_dealloc = gate_vm_dealloc;
  s_gate_q_derive = gate_q_derive;
  s_gate_q_destroy = gate_q_destroy;
  s_gate_comp_destroy = gate_comp_destroy;
  s_gate_thread_kill = rw[SLOT_SYS_THREAD_KILL];
  s_run_ready = sealing::is_sealed_as(OType::QuotaDisk, s_bin_quota) &&
                sealing::is_sealed_as(OType::EntryPoint, s_gate_thread_kill) &&
                sealing::is_sealed_as(OType::QuotaThreadMem, s_thread_quota) &&
                capability_is_valid(s_sched_derive) &&
                capability_is_valid(s_sched_register) &&
                capability_is_valid(s_sched_destroy) &&
                sealing::is_sealed_as(OType::EntryPoint, gate_vm_alloc) &&
                sealing::is_sealed_as(OType::EntryPoint, gate_vm_dealloc) &&
                sealing::is_sealed_as(OType::EntryPoint, gate_q_derive) &&
                sealing::is_sealed_as(OType::EntryPoint, gate_q_destroy) &&
                sealing::is_sealed_as(OType::EntryPoint, gate_comp_destroy);
  if (!s_run_ready) {
    out("[shell]    WARNING: the /bin view or a kernel entry `run` needs is "
        "missing; programs disabled\n");
  }

  s_worker_entry = mint_entry(gate_invoke, gate_sentry, self_comp,
                              reinterpret_cast<const void*>(&shell_worker_entry));
  if (!sealing::is_sealed_as(OType::EntryPoint, s_worker_entry)) {
    out("[shell]    worker entry mint FAILED\n");
    return -1;
  }

  // Nobody to talk to -- no `uart.read` was seeded -- so
  // do what a person would and leave; an interactive session could never end.
  const bool has_keyboard = sealing::is_sealed_as(OType::EntryPoint, s_uart_read);
  if (!has_keyboard) {
    out("[shell]    no console input available; running the demos instead\n");
    if (s_fs_ready) {
      run_fs_demo();
      run_app_demo();
    }
    run_demo();
    out("[shell]    shell exiting\n");
    return 0;
  }

  // The two halves of going to sleep on the keyboard: what `uart` invokes when
  // a key is pressed, and which thread that should wake. Without either the
  // console would sleep for good, so it polls instead (`read_input` passes
  // whatever `s_notify_entry` is, and `uart` ignores a non-entry).
  const uint64_t my_tid = invoke<uint64_t>(gate_invoke, sched_self);
  Capability notify = mint_entry(gate_invoke, gate_sentry, self_comp,
                                 reinterpret_cast<const void*>(&shell_notify_entry));
  if (my_tid != 0 && sealing::is_sealed_as(OType::EntryPoint, notify)) {
    s_my_tid = my_tid;
    s_notify_entry = notify;
  } else {
    out("[shell]    WARNING: sched.self / notify entry FAILED; console input "
        "will be polled\n");
    s_sched_block = s_sched_yield;
  }

  const WorkerConfig bg{BG_WORKERS, BG_PERIOD_US, BG_BUDGET_US, BG_CLASS,
                        BG_SLICE_US, FOREVER_US};
  const size_t started = start_workers(s_background, bg);
  out_dec("[shell]    Started ", started,
          " background workers (10/6/2 ms per second); type 'help'\n");

  console_loop();  // returns on `shutdown`

  out("[shell]    shutting down: stopping workers...\n");
  stop_workers(s_background);
  const size_t destroyed = destroy_workers(s_background);
  out_dec("[shell]    Destroyed ", destroyed, " worker quotas; shell exiting\n");
  // Returning exits the shell thread. With nothing left registered, the
  // scheduler's dispatcher exits too and the kernel's host loop returns.
  return 0;
}

}  // namespace signetos::user
