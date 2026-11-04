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
 *   compartment_main(timebase) `init`, once, before the shell's thread first
 *                              runs: records the timer frequency.
 *   compartment_main(nullptr)  the shell's own thread, dispatched by the
 *                              scheduler. A console on the UART.
 *
 * CONSOLE
 *   The shell waits for keystrokes without spending a cycle on it:
 *   `uart.read` sleeps in the scheduler until the UART interrupts (sched.cpp,
 *   DEVICE INTERRUPTS) and hands over what was typed. Commands:
 *     help       list commands
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
 *     pagetest [fill <MiB>]
 *                paging self-test (PAGE TEST below)
 *     sealtest   compartment-minted sealing self-test: the sealer service,
 *                from the shell and from a program (`run sealtest.bin`)
 *     shutdown   stop the pager and exit. Nothing is registered after that,
 *                so the dispatcher exits too and the kernel powers the
 *                machine off.
 *   In a build where `init` could not seed `uart.read` nobody is at the
 *   keyboard: the shell then just exits.
 */

#include "runtime.hpp"

namespace signetos::user {
namespace {

uint64_t s_ticks_per_us = 10;  // `time` ticks per us (/cpus timebase-frequency)
constexpr size_t LINE_MAX = 64;

// TODO This obviously isn't a real shell or a good shell, it's just enough to
// kind of test some things for now

// --- What the shell asks `init` for (user/manifest.hpp) -----------------------
// Its own quotas: the VM it lives on, thread memory for its programs' threads,
// and its CPU bandwidth -- half the machine, as an ADMIN `quota_sched` node it
// sub-divides for its programs; the kernel entries a console that starts
// threads and runs programs is made of; the services it talks to; its
// place on the disk: `/home` as an ADMIN node with all the space and inodes
// the system's own images leave free (DISK entries are met in order, so this
// one takes everything before `/bin` asks for nothing), and `/bin` as a
// 0-byte read-only view of the programs.
#define SHELL_MANIFEST(X)                                                      \
  M_QUOTA_VM(X, VM_QUOTA)                                                      \
  M_QUOTA_THREAD(X, THREAD_QUOTA, 256ULL * 1024 * 1024)                        \
  M_QUOTA_SCHED(X, SCHED_QUOTA, 50'000, 100'000,                               \
                ::signetos::init::PRIORITY_INTERACTIVE)                        \
  M_SYSCALL(X, SYS_VM_ALLOC, vm_allocate)                                      \
  M_SYSCALL(X, SYS_VM_DEALLOC, vm_deallocate)                                  \
  M_SYSCALL(X, SYS_QUOTA_VM_DERIVE, quota_vm_derive)                           \
  M_SYSCALL(X, SYS_QUOTA_VM_DESTROY, quota_vm_destroy)                         \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)                            \
  M_SYSCALL(X, SYS_COMP_CREATE, compartment_create)                            \
  M_SYSCALL(X, SYS_COMP_DESTROY, compartment_destroy)                          \
  M_SYSCALL(X, SYS_THREAD_CREATE, thread_create)                               \
  M_SYSCALL(X, SYS_THREAD_KILL, thread_kill)                                   \
  M_SYSCALL(X, SYS_SENTRY, sentry)                                             \
  M_SYSCALL(X, SYS_FAULT_INSTALL, fault_install)                               \
  M_SYSCALL(X, SYS_REVOKE_QUERY, revoke_query)                                 \
  M_SYSCALL(X, SYS_PAGE_TEST, page_test)                                       \
  M_SERVICE(X, UART_SENTRY, "uart")                                            \
  M_SERVICE_OPT(X, PAGING_STOP, "blk.paging_stop")                             \
  M_SERVICE_OPT(X, UART_READ, "uart.read")                                     \
  M_SERVICE(X, NAMING_LOOKUP, "naming.lookup")                                 \
  M_DISK(X, DISK_QUOTA, 0, perms::Load | perms::Store,                         \
         ::signetos::init::MANIFEST_ALL, ::signetos::init::MANIFEST_ALL_INODES, \
         "home")                                                               \
  M_DISK(X, BIN_DIR, 0, perms::Load, 0, 0, "bin")
// 1 GiB of address space: the shell's own image and tables, its programs'
// scheduler nodes, and -- `run <file>` -- the buffer a program is read into
// plus the VM sub-quota its compartment lives on while it runs. A program's
// thread is paid from THREAD_QUOTA. Freed memory stays charged until a sweep
// reclaims it, so both are sized for many programs, not one.
SIGNETOS_MANIFEST(SHELL_MANIFEST, 1024ULL * 1024 * 1024)

// Console state. One shell thread, so plain globals.
Capability s_gate_invoke = nullptr;
Capability s_gate_thread_create = nullptr;
Capability s_gate_revoke_query = nullptr;
Capability s_uart = nullptr;
Capability s_uart_read = nullptr;
Capability s_vm_quota = nullptr;
Capability s_thread_quota = nullptr;
Capability s_my_quota = nullptr;  // SLOT_SCHED_QUOTA: this compartment's node
Capability s_sched_derive = nullptr;
Capability s_sched_destroy = nullptr;
Capability s_sched_query = nullptr;
Capability s_sched_register = nullptr;
Capability s_sched_yield = nullptr;
Capability s_sched_block = nullptr;

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

// Runs `attempt` until `ok` accepts what it returns, giving what the shell
// has freed the chance to come back first: it comes back to its quotas only
// once a sweep has reclaimed it, and sweeps are rate limited (DESIGN.md
// §4.2). Looking at the completed epoch may sweep, so after a refusal the
// shell looks and tries again; if that is refused too, it waits for the next
// sweep, which reclaims everything freed so far, and tries a last time.
template <typename Attempt, typename Ok>
auto with_reclaim(Attempt attempt, Ok ok) {
  auto result = attempt();
  if (ok(result) || !capability_is_valid(s_gate_revoke_query)) {
    return result;
  }
  using FnQuery = decltype(&sys_revoke_query);
  const uint64_t seen = syscall::call<FnQuery>(s_gate_invoke, s_gate_revoke_query);
  result = attempt();
  if (ok(result)) {
    return result;
  }
  revoke_wait(s_gate_invoke, s_gate_revoke_query, s_sched_block, seen + 1);
  return attempt();
}

// A thread paid from the shell's thread quota, or null.
Capability new_thread(size_t stack, Capability entry, Capability arg) {
  using FnThreadCreate = decltype(&sys_thread_create);
  return with_reclaim(
      [&] {
        return syscall::call<FnThreadCreate>(s_gate_invoke,
                                             s_gate_thread_create,
                                             s_thread_quota, stack, entry, arg);
      },
      [](Capability t) { return sealing::is_sealed_as(OType::Thread, t); });
}

// Derives the scheduler node `req` asks for. Its page is paid from the
// shell's VM quota.
void derive_node(init::SchedDeriveRequest* req) {
  with_reclaim(
      [&] {
        req->status = init::SCHED_BAD_REQUEST;
        invoke<int64_t>(s_gate_invoke, s_sched_derive, bounded(req));
        return req->status;
      },
      [](int64_t status) { return status != init::SCHED_NO_MEMORY; });
}

// How many threads are registered on the scheduler node `node` and the nodes
// under it, or a negative SCHED_* status.
int64_t node_threads(Capability node) {
  init::SchedQueryRequest req{};
  req.status = init::SCHED_BAD_REQUEST;
  invoke<int64_t>(s_gate_invoke, s_sched_query, node, bounded(&req));
  return req.status == init::SCHED_OK ? static_cast<int64_t>(req.threads)
                                      : req.status;
}

// Takes back `node`, a scheduler node derived from the shell's own. A thread
// still on it stops.
int64_t destroy_sched_node(Capability node) {
  return invoke<int64_t>(s_gate_invoke, s_sched_destroy, s_my_quota, node);
}

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

// The sealer's entry points (abi.hpp, "Sealing service"), resolved by name:
// what a program that asks for `seal.*` is granted, and what `sealtest`
// uses. Null if the sealer did not come up; programs that require them are
// then not started.
Capability s_seal_mint = nullptr;
Capability s_seal_derive = nullptr;
Capability s_seal_seal = nullptr;
Capability s_seal_unseal = nullptr;

// Buffers that cross into `fs` live here rather than on the (narrowed) stack.
constexpr size_t LIST_MAX = 16;
constexpr size_t DATA_MAX = 8192;
alignas(16) init::FsDirEntry s_entries[LIST_MAX];
alignas(16) uint8_t s_data[DATA_MAX];

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
//      shell's: the same shape as a packaged image, so it loads as one (see
//      `DiskImages` in init.cpp, which does the same);
//   2. read its manifest (user/manifest.hpp) and make the program its own
//      quotas: a VM sub-quota of the shell's for it to live on, as large as
//      the manifest asks within APP_VM_MAX, and a `quota_sched` node of the
//      shell's for its thread (THE PROGRAM'S THREAD, below);
//   3. grant the manifest, entry by entry, by the policy below -- this is the
//      shell acting as a launcher, and the whole of what the program will be
//      able to reach is decided here;
//   4. `create_compartment`: compartment, code, entry sentry -- seeded with
//      `s_app_seeds`, entry i in slot RW_SLOT_SEED_BASE + i. There is no
//      directory to ask: a program holds what its creator put in its table
//      and nothing else;
//   5. start its thread -- entry: the program's entry point, argument: an
//      `AppRequest` carrying the arguments -- on its node, and sleep until
//      the thread has ended; its status comes back in the block;
//   6. destroy the compartment, destroy the quota, release the buffer, and
//      take back what step 3 granted: destroy the nodes (which removes the
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
//            Not `naming.lookup`, `sched`, `uart.read`: nothing it
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
//   vm quota the VM sub-quota of step 2, the one it lives on (the ADMIN
//            handle; the shell destroys it when the program returns).
//   cpu      its `quota_sched` node of step 2, with the bandwidth its first
//            QUOTA_SCHED entry asks for, up to APP_BUDGET_US per
//            APP_PERIOD_US and never above the interactive class. The node
//            is revocable: the shell takes it back through its own node
//            whenever it likes, and anything derived under it goes too. The
//            program cannot reach `sched.*` (above), so it can neither
//            derive under the node nor register threads on it yet.
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
//   under a `quota_sched` node of its own, carved out of the shell's
//   bandwidth -- what its manifest asks for, at most APP_BUDGET_US per
//   APP_PERIOD_US (`derive_app_node`): a program is preempted like any
//   other thread and cannot take more of the CPU than that. The shell sleeps
//   meanwhile and knows the program is done when nothing is registered on
//   the node any more (`sched.quota_query`): the scheduler unregisters a
//   thread when it ends. Then it destroys the node.
constexpr size_t APP_STACK = 64 * 1024;
constexpr uint32_t APP_BUDGET_US = 20'000;
constexpr uint32_t APP_PERIOD_US = 100'000;
constexpr uint32_t APP_PERIOD_MIN_US = 1'000;      // the periods a manifest
constexpr uint32_t APP_PERIOD_MAX_US = 1'000'000;  // may ask for
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
Capability s_gate_vm_alloc = nullptr;
Capability s_gate_vm_dealloc = nullptr;
Capability s_gate_q_derive = nullptr;
Capability s_gate_q_destroy = nullptr;
Capability s_gate_comp_create = nullptr;
Capability s_gate_comp_destroy = nullptr;
Capability s_gate_sentry = nullptr;
Capability s_gate_fault_install = nullptr;
Capability s_gate_thread_kill = nullptr;

// Sleeps until `us` have passed, or until something wakes the shell first
// (a keystroke); callers loop on whatever they are waiting for.
void sleep_us(uint64_t us) {
  invoke<int64_t>(s_gate_invoke, s_sched_block, us);
}

// A `quota_sched` node of the shell's for one program, or null: what the
// first QUOTA_SCHED entry of its manifest asks for, held to at most
// APP_BUDGET_US per APP_PERIOD_US -- the same share of the CPU over any
// period from APP_PERIOD_MIN_US to APP_PERIOD_MAX_US -- and never above the
// interactive class; exactly that share, interactive, if it asks for none
// (or for 0).
Capability derive_app_node(const init::Manifest& m) {
  uint32_t period = APP_PERIOD_US;
  uint64_t budget = APP_BUDGET_US;
  uint8_t priority = init::PRIORITY_INTERACTIVE;
  for (uint32_t i = 0; i < m.count; ++i) {
    const init::ManifestEntry& e = m.entries[i];
    if (e.kind != init::MANIFEST_QUOTA_SCHED) {
      continue;
    }
    if (e.count != 0) {
      period = e.count < APP_PERIOD_MIN_US   ? APP_PERIOD_MIN_US
               : e.count > APP_PERIOD_MAX_US ? APP_PERIOD_MAX_US
                                             : e.count;
    }
    const uint64_t most =
        static_cast<uint64_t>(APP_BUDGET_US) * period / APP_PERIOD_US;
    budget = (e.amount == 0 || e.amount > most) ? most : e.amount;
    if (e.param > priority) {  // a lower class; anything else stays interactive
      priority = e.param > init::PRIORITY_BATCH
                     ? init::PRIORITY_BATCH
                     : static_cast<uint8_t>(e.param);
    }
    break;
  }
  init::SchedDeriveRequest req{};
  req.parent = s_my_quota;
  req.node_funding = s_vm_quota;
  req.budget_us = static_cast<uint32_t>(budget);
  req.period_us = period;
  req.term_us = init::SCHED_REVOCABLE;
  req.priority_class = priority;
  derive_node(&req);
  return req.status == init::SCHED_OK ? req.out_quota : nullptr;
}

// Starts the program's thread at `entry` with `s_app_req`, registered on
// `node`. False if it could not be started, in which case nothing of it is
// left running.
bool start_app_thread(Capability entry, Capability node) {
  using FnThreadKill = decltype(&sys_thread_kill);
  // `s_app_req` sits in `.bss`, not on a stack, so it is a global capability
  // the kernel will take as the initial argument.
  Capability t = new_thread(APP_STACK, entry, bounded(&s_app_req));
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

// Sleeps until the program's thread has ended -- nothing is registered on its
// node any more -- then destroys the node, and says whether that all worked.
bool wait_app_thread(Capability node) {
  int64_t threads = 0;
  do {
    sleep_us(APP_POLL_US);
    threads = node_threads(node);
  } while (threads > 0);
  const int64_t st = threads == 0 ? destroy_sched_node(node) : threads;
  if (st != init::SCHED_OK) {
    out_dec("[shell]    run: WARNING: the program's scheduler node would "
            "not go, status -", static_cast<uint64_t>(-st), "\n");
    return false;
  }
  return true;
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
    image = with_reclaim(
        [&] {
          return syscall::call<FnAlloc>(s_gate_invoke, s_gate_vm_alloc,
                                        s_self_comp, s_vm_quota, bytes, 0);
        },
        [](Capability c) { return capability_is_valid(c); });
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

// The file-system and sealing entry points a program may ask for by name, or
// null.
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
  if (str_eq(name, "seal.mint")) return s_seal_mint;
  if (str_eq(name, "seal.derive")) return s_seal_derive;
  if (str_eq(name, "seal.seal")) return s_seal_seal;
  if (str_eq(name, "seal.unseal")) return s_seal_unseal;
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

// Step 3, one DISK entry: the directory, and a node of the shell's rooted
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

// Step 3: the manifest, entry by entry, into `s_app_seeds` by the policy
// above, `quota` and `node` being the program's own quotas of step 2. True if
// every REQUIRED entry was met; the first that was not is named on the
// console. Prints the grants on one line either way.
bool grant_manifest(const char* prog, const init::Manifest& m,
                    Capability quota, Capability node) {
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
      case init::MANIFEST_QUOTA_VM:
        cap = quota;
        break;
      case init::MANIFEST_QUOTA_SCHED:
        cap = node;
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

// Creates a compartment on `quota` from `image`, seeded with the first
// `count` of `s_app_seeds`. True with both handles filled in.
bool load_image(Capability quota, uint32_t count, Capability image,
                Capability* out_comp, Capability* out_entry) {
  const Capability seeds =
      count == 0 ? nullptr
                 : capability_set_bounds(
                       reinterpret_cast<Capability>(&s_app_seeds[0]),
                       static_cast<size_t>(count) * sizeof(Capability));
  return create_compartment(s_gate_invoke, s_gate_comp_create,
                            s_gate_comp_destroy, s_gate_vm_alloc,
                            s_gate_sentry, s_gate_fault_install, quota, seeds,
                            image, out_comp, out_entry);
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

  // 2. What it asks for, and its own quotas: the VM it lives on and the node
  //    its thread runs under (THE PROGRAM'S THREAD, above).
  init::Manifest manifest{};
  if (ok) {
    const init::CompartmentImageHeader* hdr = init::image_header(image);
    ok = hdr != nullptr && init::manifest_of(image, hdr, &manifest);
    if (!ok) {
      out("[shell]    run: not a program (no header, or a malformed "
          "manifest)\n");
    }
  }
  Capability quota = nullptr;
  if (ok) {
    size_t vm_bytes = manifest.vm_bytes == 0
                          ? APP_VM_DEFAULT
                          : static_cast<size_t>(manifest.vm_bytes);
    if (vm_bytes > APP_VM_MAX) vm_bytes = APP_VM_MAX;
    quota = with_reclaim(
        [&] {
          return syscall::call<FnQuotaDerive>(s_gate_invoke, s_gate_q_derive,
                                              s_vm_quota, vm_bytes,
                                              perms::Load | perms::Store);
        },
        [](Capability q) { return sealing::is_sealed_as(OType::QuotaVm, q); });
    ok = sealing::is_sealed_as(OType::QuotaVm, quota);
    if (!ok) {
      out("[shell]    run: no VM quota left for a program\n");
    }
  }
  Capability node = nullptr;
  if (ok) {
    node = derive_app_node(manifest);
    ok = capability_is_valid(node);
    if (!ok) {
      out("[shell]    run: no CPU bandwidth left for a program\n");
    }
  }

  // 3. What it gets.
  if (ok) {
    ok = grant_manifest(name, manifest, quota, node);
    if (!ok) {
      out("[shell]    run: ");
      out(name);
      out(" needs what this shell will not give; not started\n");
    }
  }

  // 4. The program's compartment. The seeds are all it will ever hold.
  Capability comp = nullptr;
  Capability entry = nullptr;
  if (ok) {
    ok = load_image(quota, manifest.count, image, &comp, &entry);
    if (!ok) {
      out("[shell]    run: not a program (the image was refused)\n");
    }
  }

  // 5. Run it, on a thread of its own (THE PROGRAM'S THREAD, above), and
  //    sleep until that thread has ended.
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

void print_help() {
  out("  help       this text\n"
      "  ls [dir]   list a directory (paths are under /home, the shell's root)\n"
      "  cat <f>    print a file\n"
      "  write <f> <text>   replace a file with a line of text\n"
      "  append <f> <text>  add a line of text to a file\n"
      "  mkdir <d>  make a directory\n"
      "  rm <p>     remove a file or an empty directory\n"
      "  df         the shell's disk quota: used, delegated, limit\n"
      "  run <f> [args]     load a program from /bin into a compartment "
      "of its own and run it\n"
      "  pagetest [fill <MiB>]  paging self-test\n"
      "  sealtest   compartment-minted sealing self-test (the sealer service)\n"
      "  shutdown   power the machine off\n");
}

// sealtest: compartment-minted sealing types (abi.hpp, "Sealing service";
// CORE_DESIGN.md §2.3), not part of the shell. `run sealtest.bin` checks
// keys, handles, derived rights and refusals as any client sees them; what a
// program cannot check is a type's LIFETIME, since it cannot free memory.
// This does: a page of the shell's own holds a type's record and an object
// of the type; the page is freed and, once a sweep has reclaimed it, the key
// and the handle -- both based in it -- have lost their tags and open
// nothing. The key and the handle are kept in `.bss`, which the sweep scans,
// and read back from there. Then the program half runs.
Capability s_sealtest_key = nullptr;
Capability s_sealtest_handle = nullptr;

void cmd_sealtest() {
  if (!capability_is_valid(s_seal_mint) || !capability_is_valid(s_seal_seal) ||
      !capability_is_valid(s_seal_unseal)) {
    out("[sealtest] the sealer's entry points were not found by name\n");
    return;
  }
  if (!capability_is_valid(s_gate_revoke_query) || !s_run_ready) {
    out("[sealtest] needs revoke_query and `run`\n");
    return;
  }
  using FnAlloc = decltype(&sys_vm_allocate);
  using FnDealloc = decltype(&sys_vm_deallocate);
  using FnQuery = decltype(&sys_revoke_query);
  const Capability page = with_reclaim(
      [&] {
        return syscall::call<FnAlloc>(s_gate_invoke, s_gate_vm_alloc,
                                      s_self_comp, s_vm_quota, vm::PAGE_SIZE,
                                      0);
      },
      [](Capability c) { return capability_is_valid(c); });
  if (!capability_is_valid(page)) {
    out("[sealtest] could not allocate a page\n");
    return;
  }
  const uint64_t base = capability_get_base(page);
  // The record at the start of the page, the object 64 bytes in.
  const Capability record = capability_set_bounds(page, sizeof(Capability));
  const Capability object =
      capability_set_bounds(capability_set_address(page, base + 64), 64);
  s_sealtest_key = invoke<Capability>(s_gate_invoke, s_seal_mint, record);
  s_sealtest_handle =
      invoke<Capability>(s_gate_invoke, s_seal_seal, s_sealtest_key, object);
  const Capability payload = invoke<Capability>(
      s_gate_invoke, s_seal_unseal, s_sealtest_key, s_sealtest_handle);
  bool ok = sealing::is_sealed_as(OType::TypeKey, s_sealtest_key) &&
            sealing::is_sealed_as(OType::SealedObject, s_sealtest_handle) &&
            capability_is_valid(payload) &&
            capability_get_base(payload) == base + 64 + sizeof(Capability);
  out(ok ? "[sealtest] a type on a page of the shell's: key, object, payload OK\n"
         : "[sealtest] FAILED: could not mint, seal and unseal on the page\n");

  // Free the page. Until a sweep reclaims it the type still works (the page
  // is quarantined, not unmapped); after one, nothing based in it is tagged.
  const uint64_t seen =
      syscall::call<FnQuery>(s_gate_invoke, s_gate_revoke_query);
  syscall::call<FnDealloc>(s_gate_invoke, s_gate_vm_dealloc, s_self_comp,
                           s_vm_quota, page);
  out("[sealtest] record freed; waiting for a sweep...\n");
  revoke_wait(s_gate_invoke, s_gate_revoke_query, s_sched_block, seen + 1);

  const Capability key_after =
      *reinterpret_cast<volatile Capability*>(&s_sealtest_key);
  const Capability handle_after =
      *reinterpret_cast<volatile Capability*>(&s_sealtest_handle);
  const bool key_dead = !capability_is_valid(key_after);
  const bool handle_dead = !capability_is_valid(handle_after);
  const bool opens_nothing = !capability_is_valid(
      invoke<Capability>(s_gate_invoke, s_seal_unseal, key_after, handle_after));
  out(key_dead ? "[sealtest] after the sweep the key is untagged\n"
               : "[sealtest] FAILED: the key survived the sweep\n");
  out(handle_dead ? "[sealtest] after the sweep the handle is untagged\n"
                  : "[sealtest] FAILED: the handle survived the sweep\n");
  out(opens_nothing ? "[sealtest] the dead type opens nothing\n"
                    : "[sealtest] FAILED: the dead type still opens objects\n");
  ok = ok && key_dead && handle_dead && opens_nothing;
  s_sealtest_key = nullptr;
  s_sealtest_handle = nullptr;
  out(ok ? "[sealtest] lifetime OK; now the program\n"
         : "[sealtest] lifetime FAILED; now the program\n");

  int64_t status = RUN_NOT_RUN;
  if (!cmd_run("sealtest.bin", "", &status) || status != 0) {
    out("[sealtest] FAILED: run sealtest.bin did not pass\n");
    ok = false;
  }
  out(ok ? "[sealtest] OK\n" : "[sealtest] FAILED\n");
}

// --- PAGE TEST (vm.hpp, PAGING) ----------------------------------------------
// The shell stays in RAM, as does what it allocates for itself: it was
// started before paging was. What pages is what a compartment started since
// allocates, so the test makes one, empty, and allocates for it.
//   pagetest             16 pages of data and capabilities go to swap and
//                        come back; then a capability on disk to memory that
//                        is freed is not built again when its page comes
//                        back, and one to live memory is.
//   pagetest fill <MiB>  writes MiB of memory and reads it all back: with
//                        less free RAM than that it pages for real
//                        (`make term MEM=128M PAGE_TEST=1`, then
//                        `pagetest fill 112`). Needs PAGE_TEST=1 (Makefile).
Capability s_gate_page_test = nullptr;

struct PageArena {
  Capability quota = nullptr;
  Capability comp = nullptr;
};

bool arena_open(PageArena* a, size_t bytes) {
  using FnQuotaDerive = decltype(&sys_quota_vm_derive);
  using FnCompCreate = decltype(&sys_compartment_create);
  a->quota = with_reclaim(
      [&] {
        return syscall::call<FnQuotaDerive>(s_gate_invoke, s_gate_q_derive,
                                            s_vm_quota, bytes,
                                            perms::Load | perms::Store);
      },
      [](Capability q) { return sealing::is_sealed_as(OType::QuotaVm, q); });
  if (sealing::is_sealed_as(OType::QuotaVm, a->quota)) {
    a->comp = syscall::call<FnCompCreate>(s_gate_invoke, s_gate_comp_create,
                                          a->quota, nullptr);
  }
  if (!capability_is_valid(a->comp)) {
    out("[pagetest] no compartment to allocate for\n");
    return false;
  }
  return true;
}

// Retried after a sweep: what an earlier test freed holds its addresses
// until one.
Capability arena_alloc(const PageArena& a, size_t bytes) {
  using FnAlloc = decltype(&sys_vm_allocate);
  return with_reclaim(
      [&] {
        return syscall::call<FnAlloc>(s_gate_invoke, s_gate_vm_alloc, a.comp,
                                      a.quota, bytes, 0u);
      },
      [](Capability m) { return capability_is_valid(m); });
}

void arena_close(PageArena* a) {
  using FnCompDestroy = decltype(&sys_compartment_destroy);
  using FnQuotaDestroy = decltype(&sys_quota_vm_destroy);
  if (capability_is_valid(a->comp)) {
    syscall::call<FnCompDestroy>(s_gate_invoke, s_gate_comp_destroy, a->comp);
  }
  if (capability_is_valid(a->quota)) {
    syscall::call<FnQuotaDestroy>(s_gate_invoke, s_gate_q_destroy, a->quota);
  }
}

vm::PagingStats page_stats() {
  using Fn = decltype(&sys_page_test);
  vm::PagingStats st{};
  syscall::call<Fn>(s_gate_invoke, s_gate_page_test, vm::PAGE_TEST_STATS,
                    bounded(&st));
  return st;
}

// Sends `mem`'s pages to swap and waits, up to 5 s, until they are there.
bool evict(Capability mem) {
  using Fn = decltype(&sys_page_test);
  if (syscall::call<Fn>(s_gate_invoke, s_gate_page_test, vm::PAGE_TEST_EVICT,
                        mem) == ~0ULL) {
    return false;
  }
  for (int i = 0; i < 5000 && page_stats().evicting != 0; ++i) {
    sleep_us(1000);
  }
  return page_stats().evicting == 0;
}

// Touches each page of `mem`, for pages brought in after the ones a test
// sends out: the last few brought in never go (vm.cpp, RECENT).
void touch(Capability mem) {
  auto* w = reinterpret_cast<volatile uint64_t*>(mem);
  for (size_t off = 0; off < capability_get_length(mem); off += vm::PAGE_SIZE) {
    w[off / 8] = 1;
  }
}

constexpr size_t PT_WORDS = vm::PAGE_SIZE / sizeof(uint64_t);

void pagetest_basic() {
  constexpr size_t PAGES = 16;
  PageArena a;
  if (!arena_open(&a, (PAGES + 8) * vm::PAGE_SIZE + 64 * 1024)) {
    arena_close(&a);
    return;
  }
  const Capability mem = arena_alloc(a, PAGES * vm::PAGE_SIZE);
  const Capability spacer = arena_alloc(a, 4 * vm::PAGE_SIZE);
  if (!capability_is_valid(mem) || !capability_is_valid(spacer)) {
    out("[pagetest] could not allocate\n");
    arena_close(&a);
    return;
  }
  // Each page: a capability to its own middle in its first granule, and
  // every other word its page and place.
  auto* w = reinterpret_cast<volatile uint64_t*>(mem);
  auto* c = reinterpret_cast<volatile Capability*>(mem);
  auto middle = [&](size_t p) {
    return capability_set_address(
        mem, capability_get_base(mem) + (p * vm::PAGE_SIZE) + 2048);
  };
  for (size_t p = 0; p < PAGES; ++p) {
    c[p * PT_WORDS / 2] = middle(p);
    for (size_t i = 2; i < PT_WORDS; ++i) {
      w[(p * PT_WORDS) + i] = (p << 32) | i;
    }
  }
  touch(spacer);
  const vm::PagingStats before = page_stats();
  if (!evict(mem)) {
    out("[pagetest] the pages did not go out\n");
    arena_close(&a);
    return;
  }
  const vm::PagingStats out_st = page_stats();
  size_t wrong = 0;
  for (size_t p = 0; p < PAGES; ++p) {
    const Capability got = c[p * PT_WORDS / 2];
    wrong += (capability_is_valid(got) &&
              __builtin_cheri_equal_exact(got, middle(p)))
                 ? 0
                 : 1;
    for (size_t i = 2; i < PT_WORDS; ++i) {
      wrong += (w[(p * PT_WORDS) + i] == ((p << 32) | i)) ? 0 : 1;
    }
  }
  const vm::PagingStats after = page_stats();
  const uint64_t went = out_st.writes - before.writes;
  const uint64_t came = after.reads - out_st.reads;
  out_dec("[pagetest] out and back: ", went, " pages out, ");
  out_dec("", came, " back in, ");
  out_dec("", wrong, " words or capabilities wrong");
  out(went >= PAGES && came >= PAGES && wrong == 0 ? " -- OK\n"
                                                    : " -- FAILED\n");
  arena_close(&a);
}

void pagetest_revoke() {
  PageArena a;
  if (!arena_open(&a, 8 * vm::PAGE_SIZE + 64 * 1024)) {
    arena_close(&a);
    return;
  }
  const Capability target = arena_alloc(a, vm::PAGE_SIZE);
  const Capability holder = arena_alloc(a, vm::PAGE_SIZE);
  const Capability spacer = arena_alloc(a, 4 * vm::PAGE_SIZE);
  if (!capability_is_valid(target) || !capability_is_valid(holder) ||
      !capability_is_valid(spacer)) {
    out("[pagetest] could not allocate\n");
    arena_close(&a);
    return;
  }
  auto* h = reinterpret_cast<volatile Capability*>(holder);
  h[0] = target;  // freed while the holder is on disk
  h[1] = spacer;  // live throughout
  touch(spacer);
  const vm::PagingStats before = page_stats();
  if (!evict(holder)) {
    out("[pagetest] the holder did not go out\n");
    arena_close(&a);
    return;
  }
  // Freed, then two sweeps: the first that starts after the free reclaims
  // it, once the holder has been read back and checked.
  using FnDealloc = decltype(&sys_vm_deallocate);
  using FnQuery = decltype(&sys_revoke_query);
  syscall::call<FnDealloc>(s_gate_invoke, s_gate_vm_dealloc, a.comp, a.quota,
                           target);
  const uint64_t seen =
      syscall::call<FnQuery>(s_gate_invoke, s_gate_revoke_query);
  revoke_wait(s_gate_invoke, s_gate_revoke_query, s_sched_block, seen + 2);
  const vm::PagingStats after = page_stats();
  const bool gone = !capability_is_valid(h[0]);  // the holder comes back here
  const bool kept = capability_is_valid(h[1]);
  out_dec("[pagetest] revocation: ", after.checks - before.checks,
          " pages checked on disk; ");
  out(gone ? "the freed one's capability stayed gone, "
           : "the freed one's capability CAME BACK, ");
  out(kept ? "the live one's came back" : "the live one's was LOST");
  out(after.checks > before.checks && gone && kept ? " -- OK\n"
                                                   : " -- FAILED\n");
  arena_close(&a);
}

void pagetest_fill(const char* arg) {
  constexpr size_t CHUNK = 4 * 1024 * 1024;
  constexpr size_t MAX_CHUNKS = 64;
  size_t mib = 0;
  for (; *arg >= '0' && *arg <= '9'; ++arg) {
    mib = (mib * 10) + static_cast<size_t>(*arg - '0');
  }
  const size_t chunks = (mib * 1024 * 1024 + CHUNK - 1) / CHUNK;
  if (chunks == 0 || chunks > MAX_CHUNKS) {
    out_dec("[pagetest] usage: pagetest fill <MiB>, 1 to ",
            MAX_CHUNKS * CHUNK / (1024 * 1024), "\n");
    return;
  }
  PageArena a;
  if (!arena_open(&a, (chunks * CHUNK) + (1024 * 1024))) {
    arena_close(&a);
    return;
  }
  Capability mem[MAX_CHUNKS];  // the first `chunks`, set below
  for (size_t k = 0; k < chunks; ++k) {
    mem[k] = arena_alloc(a, CHUNK);
    if (!capability_is_valid(mem[k])) {
      out("[pagetest] could not allocate\n");
      arena_close(&a);
      return;
    }
  }
  constexpr size_t PAGES = CHUNK / vm::PAGE_SIZE;
  auto mark = [](size_t k, size_t p) {
    return ((k << 32) | p) ^ 0x5A5A5A5A00000000ULL;
  };
  // One phase, writing or reading back: its time, and what paged meanwhile.
  vm::PagingStats st = page_stats();
  out_dec("[pagetest] fill: ", chunks * PAGES, " pages, with ");
  out_dec("", (st.free_frames - st.reserve) * vm::PAGE_SIZE / (1024 * 1024),
          " MiB of RAM free for them\n");
  size_t wrong = 0;
  for (int phase = 0; phase < 2; ++phase) {
    const uint64_t t0 = now_us();
    for (size_t k = 0; k < chunks; ++k) {
      auto* w = reinterpret_cast<volatile uint64_t*>(mem[k]);
      for (size_t p = 0; p < PAGES; ++p) {
        if (phase == 0) {
          w[p * PT_WORDS] = mark(k, p);
        } else {
          wrong += w[p * PT_WORDS] == mark(k, p) ? 0 : 1;
        }
      }
    }
    const vm::PagingStats now = page_stats();
    out(phase == 0 ? "[pagetest]   written" : "[pagetest]   read back");
    out_dec(" in ", (now_us() - t0) / 1000, " ms: ");
    out_dec("", now.writes - st.writes, " pages out, ");
    out_dec("", now.reads - st.reads, " in\n");
    st = now;
  }
  out_dec("[pagetest] fill: ", wrong, " wrong");
  out(wrong == 0 ? " -- OK\n" : " -- FAILED\n");
  arena_close(&a);
}

void cmd_pagetest(char* args) {
  if (!capability_is_valid(s_gate_page_test) || page_stats().slots == 0) {
    out("[pagetest] paging is off, or the kernel was built without "
        "PAGE_TEST=1\n");
    return;
  }
  char* rest = nullptr;
  const char* sub = first_word(args, &rest);
  if (str_eq(sub, "fill")) {
    pagetest_fill(rest);
  } else {
    pagetest_basic();
    pagetest_revoke();
  }
}

// Runs one command line (edited in place to split off arguments). False means
// the console should end.
bool execute(char* line) {
  char* rest = nullptr;
  const char* cmd = first_word(line, &rest);
  if (str_eq(cmd, "help")) {
    print_help();
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
  } else if (str_eq(cmd, "sealtest")) {
    cmd_sealtest();
  } else if (str_eq(cmd, "pagetest")) {
    cmd_pagetest(rest);
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

// What has been typed, once something has (`uart.read` sleeps until then);
// 0 if the console cannot sleep (its interrupt is not routed).
size_t read_input(char* buf, size_t max) {
  Capability b = capability_set_bounds(reinterpret_cast<Capability>(buf), max);
  return static_cast<size_t>(invoke<uint64_t>(s_gate_invoke, s_uart_read, b));
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
      yield();  // nothing to sleep on: poll
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

SIGNETOS_DEFAULT_FAULT_HANDLER("shell")

// TODO: This is hacky (multiplexing one-time init vs scheduled thread entry:
// `init` calls it once with the timebase, and starts the thread with no
// argument). Let's make this be nicer.
extern "C" int64_t compartment_main(Capability arg) {
  Capability* rw = rw_table();

  Capability self_comp = rw[compartment::SLOT_SELF];
  Capability vm_quota = rw[SLOT_VM_QUOTA];

  // The manifest's slots (SHELL_MANIFEST above): entry i is slot SEED_BASE + i.
  Capability thread_quota = rw[SLOT_THREAD_QUOTA];
  Capability gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  Capability gate_thread_create = rw[SLOT_SYS_THREAD_CREATE];
  Capability gate_sentry = rw[SLOT_SYS_SENTRY];
  Capability gate_fault_install = rw[SLOT_SYS_FAULT_INSTALL];
  Capability uart_sentry = rw[SLOT_UART_SENTRY];
  Capability naming_lookup = rw[SLOT_NAMING_LOOKUP];
  Capability uart_read = rw[SLOT_UART_READ];
  // For `run`: memory for the image, a sub-quota for the program's
  // compartment, and the means to create and take down the compartment.
  Capability gate_vm_alloc = rw[SLOT_SYS_VM_ALLOC];
  Capability gate_vm_dealloc = rw[SLOT_SYS_VM_DEALLOC];
  Capability gate_q_derive = rw[SLOT_SYS_QUOTA_VM_DERIVE];
  Capability gate_q_destroy = rw[SLOT_SYS_QUOTA_VM_DESTROY];
  Capability gate_comp_create = rw[SLOT_SYS_COMP_CREATE];
  Capability gate_comp_destroy = rw[SLOT_SYS_COMP_DESTROY];
  // CPU bandwidth: the compartment's own node, which every program's node is
  // derived under.
  Capability sched_quota = rw[SLOT_SCHED_QUOTA];

  if (!sealing::is_sealed_as(OType::Compartment, self_comp) ||
      !sealing::is_sealed_as(OType::QuotaVm, vm_quota) ||
      !sealing::is_sealed_as(OType::QuotaThreadMem, thread_quota) ||
      !sealing::is_sealed_as(OType::QuotaSched, sched_quota) ||
      !sealing::is_sealed_as(OType::EntryPoint, uart_sentry) ||
      !sealing::is_sealed_as(OType::EntryPoint, naming_lookup)) {
    return -1;
  }

  // One-time setup: `init` calls in with the timebase before the shell's
  // thread first runs.
  if (capability_is_valid(arg)) {
    if (capability_get_length(arg) >= sizeof(uint64_t)) {
      const uint64_t hz = *reinterpret_cast<const uint64_t*>(arg);
      if (hz >= 1'000'000) {
        s_ticks_per_us = hz / 1'000'000;
      }
    }
    return 0;
  }

  // ---- The shell's scheduled thread ----------------------------------------
  s_gate_invoke = gate_invoke;
  s_gate_thread_create = gate_thread_create;
  s_uart = uart_sentry;
  s_uart_read = uart_read;
  s_vm_quota = vm_quota;
  s_thread_quota = thread_quota;
  s_my_quota = sched_quota;

  s_sched_derive =
      lookup_name(gate_invoke, naming_lookup, "sched.quota_derive");
  s_sched_destroy =
      lookup_name(gate_invoke, naming_lookup, "sched.quota_destroy");
  s_sched_query = lookup_name(gate_invoke, naming_lookup, "sched.quota_query");
  s_sched_register =
      lookup_name(gate_invoke, naming_lookup, "sched.thread_register");
  s_sched_yield = lookup_name(gate_invoke, naming_lookup, "sched.yield");
  s_sched_block = lookup_name(gate_invoke, naming_lookup, "sched.block");
  if (!capability_is_valid(s_sched_derive) ||
      !capability_is_valid(s_sched_destroy) ||
      !capability_is_valid(s_sched_query) ||
      !capability_is_valid(s_sched_register) ||
      !capability_is_valid(s_sched_yield) ||
      !capability_is_valid(s_sched_block)) {
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

  // The sealer: granted to programs that ask, and used by `sealtest`. Not
  // having it costs nothing else.
  s_seal_mint = lookup_name(gate_invoke, naming_lookup, "seal.mint");
  s_seal_derive = lookup_name(gate_invoke, naming_lookup, "seal.derive");
  s_seal_seal = lookup_name(gate_invoke, naming_lookup, "seal.seal");
  s_seal_unseal = lookup_name(gate_invoke, naming_lookup, "seal.unseal");
  if (!capability_is_valid(s_seal_mint) || !capability_is_valid(s_seal_derive) ||
      !capability_is_valid(s_seal_seal) || !capability_is_valid(s_seal_unseal)) {
    out("[shell]    WARNING: seal.* not found by name; programs cannot be "
        "granted sealing\n");
  }

  // Programs: `run` needs the file system above, the view of `/bin`, and all
  // of these. The manifest asks `init` for every one; a system that will not
  // give them just loses the command.
  s_self_comp = self_comp;
  s_gate_vm_alloc = gate_vm_alloc;
  s_gate_vm_dealloc = gate_vm_dealloc;
  s_gate_q_derive = gate_q_derive;
  s_gate_q_destroy = gate_q_destroy;
  s_gate_comp_create = gate_comp_create;
  s_gate_comp_destroy = gate_comp_destroy;
  s_gate_sentry = gate_sentry;
  s_gate_fault_install = gate_fault_install;
  s_gate_thread_kill = rw[SLOT_SYS_THREAD_KILL];
  s_gate_revoke_query = rw[SLOT_SYS_REVOKE_QUERY];
  s_gate_page_test = rw[SLOT_SYS_PAGE_TEST];
  s_run_ready = sealing::is_sealed_as(OType::QuotaDisk, s_bin_quota) &&
                sealing::is_sealed_as(OType::EntryPoint, s_gate_thread_kill) &&
                sealing::is_sealed_as(OType::QuotaThreadMem, s_thread_quota) &&
                capability_is_valid(s_sched_derive) &&
                capability_is_valid(s_sched_register) &&
                capability_is_valid(s_sched_destroy) &&
                capability_is_valid(s_sched_query) &&
                sealing::is_sealed_as(OType::EntryPoint, gate_vm_alloc) &&
                sealing::is_sealed_as(OType::EntryPoint, gate_vm_dealloc) &&
                sealing::is_sealed_as(OType::EntryPoint, gate_q_derive) &&
                sealing::is_sealed_as(OType::EntryPoint, gate_q_destroy) &&
                sealing::is_sealed_as(OType::EntryPoint, gate_comp_create) &&
                sealing::is_sealed_as(OType::EntryPoint, gate_comp_destroy) &&
                sealing::is_sealed_as(OType::EntryPoint, gate_sentry) &&
                sealing::is_sealed_as(OType::EntryPoint, gate_fault_install);
  if (!s_run_ready) {
    out("[shell]    WARNING: the /bin view or a kernel entry `run` needs is "
        "missing; programs disabled\n");
  }

  // Nobody to talk to -- no `uart.read` was seeded -- so
  // do what a person would and leave; an interactive session could never end.
  const bool has_keyboard = sealing::is_sealed_as(OType::EntryPoint, s_uart_read);
  if (!has_keyboard) {
    out("[shell]    no console input available; shell exiting\n");
    return 0;
  }

  out("[shell]    Ready; type 'help'\n");
  console_loop();  // returns on `shutdown`

  out("[shell]    shutting down; shell exiting\n");
  // The pager's thread too, or the machine would never stop (blk.cpp, PAGING).
  if (capability_is_valid(rw[SLOT_PAGING_STOP])) {
    invoke<int64_t>(gate_invoke, rw[SLOT_PAGING_STOP]);
  }
  // Returning exits the shell thread. With nothing left registered, the
  // scheduler's dispatcher exits too and the kernel's host loop returns.
  return 0;
}

}  // namespace signetos::user
