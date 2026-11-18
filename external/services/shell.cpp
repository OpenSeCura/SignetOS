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
 *     ls [dir], cat, write, append, mkdir, rm, mv, freeze, df
 *                files (FILES below)
 *     run <prog> [<request>=<path> ...] [args], link, unlink, quota
 *                programs from /bin (Programs below, launch.hpp)
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

#include "launch.hpp"
#include "runtime.hpp"

namespace signetos::user {
namespace {

uint64_t s_ticks_per_us = 10;  // `time` ticks per us (/cpus timebase-frequency)

// TODO This obviously isn't a real shell or a good shell, it's just enough to
// kind of test some things for now

// --- What the shell asks `init` for (user/manifest.hpp) -----------------------
// Its own quotas: the VM it lives on, thread memory for its programs' threads,
// and its CPU bandwidth -- half the machine, as an ADMIN `quota_sched` node it
// sub-divides for its programs; the kernel entries a console that starts
// threads and runs programs is made of; the services it talks to; and the
// disk quota, /home, /apps (programs' own) and /bin (read-only), all with
// LINK, so that what is in them can be linked for a program (launch.hpp).
#if defined(SIGNETOS_PAGING)
#define SHELL_PAGING_MANIFEST(X)                                               \
  M_SYSCALL(X, SYS_PAGE_TEST, page_test)                                       \
  M_SERVICE_OPT(X, PAGING_STOP, "blk.paging_stop")
#else
#define SHELL_PAGING_MANIFEST(X)
#endif
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
  M_SYSCALL(X, SYS_REVOKE_QUERY, revoke_query)                                 \
  M_SYSCALL(X, SYS_REVOKE_START, revoke_start)                                 \
  M_SERVICE_OPT(X, SWEEPER_STOP, "sweeper.stop")                               \
  SHELL_PAGING_MANIFEST(X)                                                     \
  M_SERVICE(X, UART_SENTRY, "uart")                                            \
  M_SERVICE_OPT(X, UART_READ, "uart.read")                                     \
  M_SERVICE(X, NAMING_LOOKUP, "naming.lookup")                                 \
  M_QUOTA_DISK(X, DISK, 0, ::signetos::init::FS_ALL, "disk")                   \
  M_DIR(X, HOME, 0, ::signetos::init::FS_ALL | ::signetos::init::FS_LINK,      \
        "home")                                                                \
  M_DIR(X, BIN, 0, ::signetos::init::FS_READ | ::signetos::init::FS_LINK,      \
        "bin")                                                                 \
  M_DIR(X, APPS, 0, ::signetos::init::FS_ALL | ::signetos::init::FS_LINK,      \
        "apps")
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
Capability s_gate_revoke_start = nullptr;
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
launch::Starter s_starter{};  // what `run` starts programs with (launch.hpp)

[[maybe_unused]] inline uint64_t now_us() {  // only `pagetest` uses it
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

// Runs `attempt` until `ok` accepts what it returns, letting what the shell
// freed come back first (launch.hpp).
template <typename Attempt, typename Ok>
auto with_reclaim(Attempt attempt, Ok ok) {
  return launch::with_reclaim(s_starter, attempt, ok);
}

// --- Files: clients of fs.* ----------------------------------------------------

// FILES: paths start at /home, /bin, /apps or /disk (the disk quota); paths
// without a leading '/' are under /home. The disk quota pays for what the
// shell writes. Commands close the handles they open.
struct Root {
  const char* name;
  Capability handle;
};
Root s_roots[] = {{"home", nullptr}, {"bin", nullptr}, {"apps", nullptr},
                  {"disk", nullptr}};
constexpr size_t ROOT_HOME = 0;
constexpr size_t ROOT_BIN = 1;
constexpr size_t ROOT_APPS = 2;
constexpr size_t ROOT_DISK = 3;
Capability s_fs[init::FS_CALLS];  // fs entry points, indexed by FS_CALL_*
bool s_fs_ready = false;

// The sealer's entry points (abi.hpp, "Sealing service"), resolved by name:
// what a program that asks for `seal.*` is granted, and what `sealtest`
// uses. Null if the sealer did not come up; programs that require them are
// then not started.
Capability s_seal_mint = nullptr;
Capability s_seal_derive = nullptr;
Capability s_seal_seal = nullptr;
Capability s_seal_unseal = nullptr;

// Buffers that cross into `fs` live here rather than on the (narrowed) stack:
// a chunk of a file for `cat`, a page of a directory for `ls`.
constexpr size_t DATA_MAX = 8192;
alignas(16) uint8_t s_data[DATA_MAX];

// Zeroed memory of the shell's, `bytes` of it at least, or null; for what
// does not fit in `s_data`.
char* alloc_bytes(size_t bytes) {
  using FnAlloc = decltype(&sys_vm_allocate);
  const size_t size = (bytes + vm::PAGE_SIZE - 1) & ~(vm::PAGE_SIZE - 1);
  const Capability memory = with_reclaim(
      [&] {
        return syscall::call<FnAlloc>(s_starter.invoke, s_starter.vm_allocate,
                                      s_starter.self, s_starter.vm_quota, size,
                                      0);
      },
      [](Capability result) { return capability_is_valid(result); });
  return capability_is_valid(memory) ? static_cast<char*>(memory) : nullptr;
}

void free_bytes(char* memory) { launch::release(s_starter, memory); }

// Calls fs entry point `call` (FS_CALL_*).
template <typename R = int64_t, typename... A>
R fs(uint32_t call, A... args) {
  return invoke<R>(s_gate_invoke, s_fs[call], args...);
}

// FS_OK if `handle` is valid, else the error it carries.
int64_t status_of(Capability handle) {
  return capability_is_valid(handle) ? init::FS_OK
                                     : init::cap_error(handle, init::FS_INVALID);
}

Capability region(void* start, size_t length) {
  return capability_set_bounds(reinterpret_cast<Capability>(start), length);
}

// A handle the shell opened, closed when this goes out of scope.
struct ScopedHandle {
  Capability handle = nullptr;
  ~ScopedHandle() {
    if (capability_is_valid(handle)) {
      fs(init::FS_CALL_CLOSE, handle);
    }
  }
};

const char* fs_status_name(int64_t status) {
  return launch::status_name(status);
}

void fs_fail(const char* what, int64_t status) {
  out("[shell]    ");
  out(what);
  out(": ");
  out(fs_status_name(status));
  out("\n");
}

// The root handle `path` starts at, with the rest of the path in `*rest`.
Capability resolve(const char* path, const char** rest) {
  *rest = path;
  if (*path != '/') {
    return s_roots[ROOT_HOME].handle;
  }
  for (const Root& root : s_roots) {
    size_t length = 0;
    while (root.name[length] != '\0' && root.name[length] == path[1 + length]) {
      ++length;
    }
    if (root.name[length] == '\0' &&
        (path[1 + length] == '\0' || path[1 + length] == '/')) {
      *rest = path[1 + length] == '/' ? path + 2 + length : path + 1 + length;
      return root.handle;
    }
  }
  return nullptr;
}

// Opens `path` with `rights`, paid for by the shell's memory quota.
int64_t open_path(const char* path, uint32_t rights, Capability* handle) {
  const char* rest = nullptr;
  const Capability from = resolve(path, &rest);
  if (from == nullptr) {
    return init::FS_NOT_FOUND;
  }
  *handle = fs<Capability>(init::FS_CALL_OPEN, from, ro_str(rest), rights,
                           s_vm_quota);
  return status_of(*handle);
}

// Creates a file (or a directory with FS_CREATE_DIR), paid by the disk quota.
int64_t create_path(const char* path, uint32_t flags, Capability* handle) {
  const char* rest = nullptr;
  const Capability dir = resolve(path, &rest);
  if (dir == nullptr) {
    return init::FS_NOT_FOUND;
  }
  *handle = fs<Capability>(init::FS_CALL_CREATE, dir, ro_str(rest),
                           s_roots[ROOT_DISK].handle, flags, s_vm_quota);
  return status_of(*handle);
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

// `ls /` lists the roots, `ls /disk` the quotas; the default is /home. A
// buffer-full of entries at a time, until fs has given them all.
void cmd_ls(const char* path) {
  if (!fs_available()) {
    return;
  }
  if (str_eq(path, "/")) {
    for (const Root& root : s_roots) {
      out("  ");
      out(root.name);
      out("/\n");
    }
    return;
  }
  const char* rest = nullptr;
  const Capability from = resolve(path, &rest);
  char* buf = reinterpret_cast<char*>(s_data);
  uint64_t bytes = DATA_MAX;
  char* big = nullptr;  // for an entry whose name does not fit in `s_data`
  uint64_t total = 0;
  int64_t status = from == nullptr ? init::FS_NOT_FOUND : init::FS_OK;
  while (status == init::FS_OK) {
    const int64_t count = fs(init::FS_CALL_LIST, from, ro_str(rest),
                             region(buf, bytes), bytes, total);
    if (count == init::FS_TOO_LARGE) {  // fs wrote what the entry needs
      bytes = init::fs_dir_entry_bytes(
          reinterpret_cast<const init::FsDirEntry*>(buf)->name_length);
      free_bytes(big);
      big = alloc_bytes(bytes);
      buf = big;
      status = big == nullptr ? init::FS_NO_MEMORY : init::FS_OK;
      continue;
    }
    if (count <= 0) {
      status = count;
      break;
    }
    const char* at = buf;
    for (int64_t i = 0; i < count; ++i) {
      const auto& entry = *reinterpret_cast<const init::FsDirEntry*>(at);
      out("  ");
      out(at + sizeof(init::FsDirEntry));
      if ((entry.flags & init::FS_ENTRY_DIR) != 0) {
        out("/");
      } else if ((entry.flags & init::FS_ENTRY_LINK) != 0) {
        out("  link");
      } else if ((entry.flags & init::FS_ENTRY_QUOTA) != 0) {
        out_dec("  quota of ", entry.size, " bytes");
      } else {
        out_dec("  ", entry.size, " bytes");
      }
      out((entry.flags & init::FS_ENTRY_FROZEN) != 0 ? " (frozen)\n" : "\n");
      at += init::fs_dir_entry_bytes(entry.name_length);
    }
    total += static_cast<uint64_t>(count);
  }
  free_bytes(big);
  if (status != init::FS_OK) {
    fs_fail("ls", status);
    return;
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
  ScopedHandle dir;
  const int64_t status = create_path(path, init::FS_CREATE_DIR, &dir.handle);
  if (status != init::FS_OK) {
    fs_fail("mkdir", status);
  }
}

void cmd_cat(const char* path) {
  if (!fs_available()) {
    return;
  }
  if (*path == '\0') {
    out("[shell]    usage: cat <file>\n");
    return;
  }
  ScopedHandle file;
  int64_t status = open_path(path, init::FS_READ, &file.handle);
  for (uint64_t offset = 0; status == init::FS_OK;) {
    const int64_t bytes_read =
        fs(init::FS_CALL_READ, file.handle, region(s_data, DATA_MAX - 1),
           offset, uint64_t{DATA_MAX - 1});
    if (bytes_read <= 0) {
      status = bytes_read;
      break;
    }
    s_data[bytes_read] = '\0';
    out(reinterpret_cast<const char*>(s_data));
    offset += static_cast<uint64_t>(bytes_read);
  }
  if (status != init::FS_OK) {
    fs_fail("cat", status);
  }
}

// `write` replaces the file with a line of text; `append` adds the line. The
// text is written from the command line itself, its NUL made the newline.
void cmd_write(const char* path, char* text, bool append) {
  if (!fs_available()) {
    return;
  }
  if (*path == '\0') {
    out(append ? "[shell]    usage: append <file> <text>\n"
               : "[shell]    usage: write <file> <text>\n");
    return;
  }
  ScopedHandle file;
  int64_t status =
      open_path(path, append ? init::FS_ADD : init::FS_CHANGE, &file.handle);
  if (status == init::FS_OK && !append) {
    // a new one takes its place
    status = fs(init::FS_CALL_REMOVE, file.handle, ro_str(""));
    status = status == init::FS_OK ? init::FS_NOT_FOUND : status;
  }
  ScopedHandle created;
  if (status == init::FS_NOT_FOUND) {
    status = create_path(path, 0, &created.handle);
  }
  size_t length = 0;
  while (text[length] != '\0') {
    ++length;
  }
  text[length++] = '\n';
  const int64_t written =
      status != init::FS_OK
          ? status
          : fs(init::FS_CALL_WRITE,
               capability_is_valid(created.handle) ? created.handle
                                                   : file.handle,
               region(text, length), init::FS_APPEND, uint64_t{length},
               s_roots[ROOT_DISK].handle);
  text[length - 1] = '\0';
  if (written < 0) {
    fs_fail(append ? "append" : "write", written);
  } else {
    out_dec("[shell]    ", static_cast<uint64_t>(written), " bytes written\n");
  }
}

// True for the shell's roots ("/home", "/apps", ...), which rm and mv refuse.
bool is_root(const char* path) {
  const char* rest = nullptr;
  return resolve(path, &rest) != nullptr && *rest == '\0';
}

// Removes a file, a directory and its contents, a quota, or a link (not what
// it names).
void cmd_rm(const char* path) {
  if (!fs_available()) {
    return;
  }
  if (*path == '\0' || is_root(path)) {
    out("[shell]    usage: rm <path>, not one of the shell's roots\n");
    return;
  }
  const char* rest = nullptr;
  const Capability from = resolve(path, &rest);
  const int64_t status = from == nullptr
                             ? init::FS_NOT_FOUND
                             : fs(init::FS_CALL_REMOVE, from, ro_str(rest));
  if (status != init::FS_OK) {
    fs_fail("rm", status);
  }
}

void cmd_mv(const char* from, const char* to) {
  if (!fs_available()) {
    return;
  }
  if (*from == '\0' || *to == '\0' || is_root(from)) {
    out("[shell]    usage: mv <from> <to>, not one of the shell's roots\n");
    return;
  }
  const char* from_rest = nullptr;
  const Capability from_dir = resolve(from, &from_rest);
  const char* rest = nullptr;
  const Capability dir = resolve(to, &rest);
  // The disk quota pays for a long new name (fs.move, abi.hpp).
  const int64_t status =
      from_dir == nullptr || dir == nullptr
          ? init::FS_NOT_FOUND
          : fs(init::FS_CALL_MOVE, from_dir, ro_str(from_rest), dir,
               ro_str(rest), s_roots[ROOT_DISK].handle);
  if (status != init::FS_OK) {
    fs_fail("mv", status);
  }
}

void cmd_freeze(const char* path) {
  if (!fs_available()) {
    return;
  }
  ScopedHandle file;
  int64_t status = open_path(path, init::FS_CHANGE, &file.handle);
  if (status == init::FS_OK) {
    status = fs(init::FS_CALL_FREEZE, file.handle);
  }
  if (status != init::FS_OK) {
    fs_fail("freeze", status);
  }
}

void cmd_df() {
  if (!fs_available()) {
    return;
  }
  init::FsStat stat{};
  const int64_t status =
      fs(init::FS_CALL_STAT, s_roots[ROOT_DISK].handle, bounded(&stat));
  if (status != init::FS_OK) {
    fs_fail("df", status);
    return;
  }
  out_dec("[shell]    disk quota: ", stat.used / 1024, " KiB used of ");
  out_dec("", stat.size / 1024, " KiB (quotas made out of it count as used)\n");
}

// --- Programs ------------------------------------------------------------------

// `run <prog> [<request>=<path> ...] [args]` starts /bin/<prog>.bin with
// launch.hpp and waits for it. Each `<request>=<path>` gives the program that
// file or directory for this run; `link <prog> <request>=<path>` gives it for
// good, and `unlink` takes it back; `quota <prog> <bytes>` resizes its own
// quota. A program can be given only what the shell holds: its roots, its
// quotas, and the services in `s_services` -- the console, fs.* and seal.*.
// Not `naming.lookup`, `sched`, `uart.read`: nothing it could reach further
// with.
bool s_run_ready = false;
Capability s_self_comp = nullptr;
Capability s_gate_vm_alloc = nullptr;
Capability s_gate_vm_dealloc = nullptr;
Capability s_gate_q_derive = nullptr;
Capability s_gate_q_destroy = nullptr;
Capability s_gate_comp_create = nullptr;
Capability s_gate_comp_destroy = nullptr;
Capability s_gate_thread_kill = nullptr;
launch::Service s_services[1 + init::FS_CALLS + 4];
constexpr size_t PICKS_MAX = 8;

// Sleeps until `us` have passed, or until something wakes the shell first
// (a keystroke); callers loop on whatever they are waiting for.
[[maybe_unused]] void sleep_us(uint64_t us) {  // only `pagetest` uses it
  invoke<int64_t>(s_gate_invoke, s_sched_block, us);
}

// "65536", "64K" or "4M".
uint64_t parse_bytes(const char* text) {
  uint64_t value = 0;
  for (; *text >= '0' && *text <= '9'; ++text) {
    value = value * 10 + static_cast<uint64_t>(*text - '0');
  }
  return *text == 'K' ? value << 10 : *text == 'M' ? value << 20 : value;
}

// Whether the word at `text` is `<request>=<path>`.
bool is_pick(const char* text) {
  for (const char* cursor = text; *cursor != '\0' && *cursor != ' '; ++cursor) {
    if (*cursor == '/') {
      return false;
    }
    if (*cursor == '=') {
      return cursor != text && cursor[1] != '\0' && cursor[1] != ' ';
    }
  }
  return false;
}

// Splits `<request>=<path>` in place: the request stays in `word`.
bool split_pick(char* word, char** path) {
  if (!is_pick(word)) {
    return false;
  }
  char* cursor = word;
  while (*cursor != '=') {
    ++cursor;
  }
  *cursor = '\0';
  *path = cursor + 1;
  return true;
}

bool run_available() {
  if (!s_run_ready) {
    out("[shell]    programs are disabled (see the warning at start)\n");
  }
  return fs_available() && s_run_ready;
}

void cmd_run(char* line) {
  if (!run_available()) {
    return;
  }
  char* rest = nullptr;
  const char* name = first_word(line, &rest);
  if (*name == '\0') {
    out("[shell]    usage: run <prog> [<request>=<path> ...] [args]\n");
    return;
  }
  launch::Pick picks[PICKS_MAX];
  ScopedHandle handles[PICKS_MAX];
  size_t pick_count = 0;
  for (; pick_count < PICKS_MAX && is_pick(rest); ++pick_count) {
    char* request = first_word(rest, &rest);
    char* path = nullptr;
    split_pick(request, &path);
    const int64_t status =
        open_path(path, init::FS_ALL, &handles[pick_count].handle);
    if (status != init::FS_OK) {
      fs_fail(path, status);
      return;
    }
    picks[pick_count] = launch::Pick{request, handles[pick_count].handle};
  }
  int64_t exit_status = launch::NOT_RUN;
  launch::run(s_starter, name, picks, pick_count, rest, &exit_status);
}

void cmd_link(char* args) {
  if (!run_available()) {
    return;
  }
  char* rest = nullptr;
  const char* program = first_word(args, &rest);
  char* request = first_word(rest, &rest);
  char* path = nullptr;
  if (*program == '\0' || !split_pick(request, &path)) {
    out("[shell]    usage: link <prog> <request>=<path>\n");
    return;
  }
  ScopedHandle target;
  int64_t status =
      open_path(path, init::FS_ALL | init::FS_LINK, &target.handle);
  if (status == init::FS_OK) {
    status = launch::link(s_starter, program, request, target.handle);
  }
  if (status != init::FS_OK) {
    fs_fail("link", status);
    return;
  }
  out("[shell]    ");
  out(program);
  out(": ");
  out(request);
  out(" linked to ");
  out(path);
  out("\n");
}

void cmd_unlink(char* args) {
  if (!run_available()) {
    return;
  }
  char* request = nullptr;
  const char* program = first_word(args, &request);
  if (*program == '\0' || *request == '\0') {
    out("[shell]    usage: unlink <prog> <request>\n");
    return;
  }
  const int64_t status = launch::unlink(s_starter, program, request);
  if (status != init::FS_OK) {
    fs_fail("unlink", status);
    return;
  }
  out("[shell]    ");
  out(program);
  out(": ");
  out(request);
  out(" unlinked\n");
}

void cmd_quota(char* args) {
  if (!run_available()) {
    return;
  }
  char* size = nullptr;
  const char* program = first_word(args, &size);
  if (*program == '\0' || *size < '0' || *size > '9') {
    out("[shell]    usage: quota <prog> <bytes>, e.g. 64K or 4M\n");
    return;
  }
  const uint64_t bytes = parse_bytes(size);
  const int64_t status = launch::resize_quota(s_starter, program, bytes);
  if (status != init::FS_OK) {
    fs_fail("quota", status);
    return;
  }
  out("[shell]    ");
  out(program);
  out_dec("'s quota is now ", bytes / 1024, " KiB\n");
}

void print_help() {
  out("  help       this text\n"
      "  ls [dir]   list a directory; paths start at /home, /bin, /apps or\n"
      "             /disk (the disk quota), and are under /home otherwise\n"
      "  cat <f>    print a file\n"
      "  write <f> <text>   replace a file with a line of text\n"
      "  append <f> <text>  add a line of text to a file\n"
      "  mkdir <d>  make a directory\n"
      "  rm <p>     remove a file, a directory and all in it, a link, or a quota\n"
      "             that pays for nothing\n"
      "  mv <p> <q> move or rename\n"
      "  freeze <f> make a file read-only for good\n"
      "  df         the disk quota: used and limit\n"
      "  run <prog> [<request>=<path> ...] [args]\n"
      "             run a program with its own /apps/<id>/own and quota <id>,\n"
      "             its links, and each <path> as <request> for this run\n"
      "  link <prog> <request>=<path>  give it <path> as <request> for good\n"
      "  unlink <prog> <request>       take that back\n"
      "  quota <prog> <bytes>          resize its own quota (64K, 4M)\n"
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
  if (!capability_is_valid(s_gate_revoke_query) ||
      !capability_is_valid(s_gate_revoke_start) || !s_run_ready) {
    out("[sealtest] needs revoke_query, revoke_start and `run`\n");
    return;
  }
  using FnAlloc = decltype(&sys_vm_allocate);
  using FnDealloc = decltype(&sys_vm_deallocate);
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
  // is quarantined, not unmapped); after one that started after the free,
  // nothing based in it is tagged.
  syscall::call<FnDealloc>(s_gate_invoke, s_gate_vm_dealloc, s_self_comp,
                           s_vm_quota, page);
  out("[sealtest] record freed; waiting for a sweep...\n");
  revoke_sweep(s_gate_invoke, s_gate_revoke_start, s_gate_revoke_query,
               s_sched_block);

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

  int64_t status = launch::NOT_RUN;
  if (!launch::run(s_starter, "sealtest.bin", nullptr, 0, "", &status) ||
      status != 0) {
    out("[sealtest] FAILED: run sealtest.bin did not pass\n");
    ok = false;
  }
  out(ok ? "[sealtest] OK\n" : "[sealtest] FAILED\n");
}

// --- PAGE TEST (vm.hpp, PAGING) ----------------------------------------------
// The shell stays in RAM, as does what it allocates for itself: `init` did
// not make it pageable. What pages is what a pageable compartment allocates,
// so the test makes one, empty, and allocates for it.
//   pagetest             16 pages of data and capabilities go to swap and
//                        come back; then a capability on disk to memory that
//                        is freed is not built again when its page comes
//                        back, and one to live memory is.
//   pagetest fill <MiB>  writes MiB of memory and reads it all back: with
//                        less free RAM than that it pages for real
//                        (`make term MEM=128M PAGE_TEST=1`, then
//                        `pagetest fill 112`). Needs PAGE_TEST=1 (Makefile).
#if defined(SIGNETOS_PAGING)
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
    // No image: an empty, pageable compartment, with the full handle, for
    // the shell to allocate into itself.
    a->comp = syscall::call<FnCompCreate>(s_gate_invoke, s_gate_comp_create,
                                          a->quota, nullptr, nullptr, nullptr,
                                          COMPARTMENT_PAGEABLE);
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

// One of the kernel's paging counts (vm.hpp, PAGE_TEST_*), or ~0 if refused.
uint64_t page_count(uint64_t which) {
  using Fn = decltype(&sys_page_test);
  return syscall::call<Fn>(s_gate_invoke, s_gate_page_test, which, nullptr);
}

// The counts a test compares before and after. All zero if the kernel
// refuses: paging is off, or it was built without PAGE_TEST.
struct PagingStats {
  uint64_t slots;
  uint64_t free_frames;
  uint64_t reserve;
  uint64_t reads;
  uint64_t writes;
  uint64_t checks;
  uint64_t digest_errors;
};
PagingStats page_stats() {
  PagingStats st{};
  if (page_count(vm::PAGE_TEST_SLOTS) == ~0ULL) {
    return st;
  }
  st.slots = page_count(vm::PAGE_TEST_SLOTS);
  st.free_frames = page_count(vm::PAGE_TEST_FREE_FRAMES);
  st.reserve = page_count(vm::PAGE_TEST_RESERVE);
  st.reads = page_count(vm::PAGE_TEST_READS);
  st.writes = page_count(vm::PAGE_TEST_WRITES);
  st.checks = page_count(vm::PAGE_TEST_CHECKS);
  st.digest_errors = page_count(vm::PAGE_TEST_DIGEST_ERRORS);
  return st;
}

// Sends `mem`'s pages to swap and waits, up to 5 s, until they are there.
bool evict(Capability mem) {
  using Fn = decltype(&sys_page_test);
  if (syscall::call<Fn>(s_gate_invoke, s_gate_page_test, vm::PAGE_TEST_EVICT,
                        mem) == ~0ULL) {
    return false;
  }
  for (int i = 0; i < 5000 && page_count(vm::PAGE_TEST_EVICTING) != 0; ++i) {
    sleep_us(1000);
  }
  return page_count(vm::PAGE_TEST_EVICTING) == 0;
}

// Touches each page of `mem`, for pages brought in after the ones a test
// sends out: the last few brought in never go (paging.cpp, RECENT).
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
  // Counted from before the pages are written: the pager may send one out
  // on its own (vm.hpp, FRAMES) before the test asks it to.
  const PagingStats before = page_stats();
  for (size_t p = 0; p < PAGES; ++p) {
    c[p * PT_WORDS / 2] = middle(p);
    for (size_t i = 2; i < PT_WORDS; ++i) {
      w[(p * PT_WORDS) + i] = (p << 32) | i;
    }
  }
  touch(spacer);
  if (!evict(mem)) {
    out("[pagetest] the pages did not go out\n");
    arena_close(&a);
    return;
  }
  const PagingStats out_st = page_stats();
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
  const PagingStats after = page_stats();
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
  const PagingStats before = page_stats();
  if (!evict(holder)) {
    out("[pagetest] the holder did not go out\n");
    arena_close(&a);
    return;
  }
  // Freed, then a sweep: one that starts after the free reclaims it, once
  // the holder has been read back and checked.
  using FnDealloc = decltype(&sys_vm_deallocate);
  syscall::call<FnDealloc>(s_gate_invoke, s_gate_vm_dealloc, a.comp, a.quota,
                           target);
  revoke_sweep(s_gate_invoke, s_gate_revoke_start, s_gate_revoke_query,
               s_sched_block);
  const PagingStats after = page_stats();
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
      out("[pagetest] could not allocate: no more pageable memory than swap "
          "holds (vm.hpp, SWAP)\n");
      arena_close(&a);
      return;
    }
  }
  constexpr size_t PAGES = CHUNK / vm::PAGE_SIZE;
  auto mark = [](size_t k, size_t p) {
    return ((k << 32) | p) ^ 0x5A5A5A5A00000000ULL;
  };
  // One phase, writing or reading back: its time, and what paged meanwhile.
  PagingStats st = page_stats();
  const uint64_t spare =
      st.free_frames > st.reserve ? st.free_frames - st.reserve : 0;
  out_dec("[pagetest] fill: ", chunks * PAGES, " pages, with ");
  out_dec("", spare * vm::PAGE_SIZE / (1024 * 1024),
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
    const PagingStats now = page_stats();
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
  s_gate_page_test = rw_table()[SLOT_SYS_PAGE_TEST];
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
#else   // !SIGNETOS_PAGING
void cmd_pagetest(char*) {
  out("[pagetest] this system was built without paging (PAGING=0)\n");
}
#endif  // SIGNETOS_PAGING

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
  } else if (str_eq(cmd, "mv")) {
    char* to = nullptr;
    const char* from = first_word(rest, &to);
    cmd_mv(from, to);
  } else if (str_eq(cmd, "freeze")) {
    cmd_freeze(rest);
  } else if (str_eq(cmd, "df")) {
    cmd_df();
  } else if (str_eq(cmd, "run")) {
    cmd_run(rest);
  } else if (str_eq(cmd, "link")) {
    cmd_link(rest);
  } else if (str_eq(cmd, "unlink")) {
    cmd_unlink(rest);
  } else if (str_eq(cmd, "quota")) {
    cmd_quota(rest);
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

// The line being typed: a small buffer of the shell's at first, then memory
// twice the size whenever it fills up.
char s_first_line[256];
char* s_line = s_first_line;
size_t s_line_size = sizeof(s_first_line);

// Room in `s_line`, which holds `length` characters, for one more and a NUL;
// false if there is no memory for it.
bool line_room(size_t length) {
  if (length + 2 <= s_line_size) {
    return true;
  }
  const size_t size =
      s_line_size < vm::PAGE_SIZE ? vm::PAGE_SIZE : 2 * s_line_size;
  char* const bigger = alloc_bytes(size);
  if (bigger == nullptr) {
    return false;
  }
  for (size_t i = 0; i < length; ++i) {
    bigger[i] = s_line[i];
  }
  if (s_line != s_first_line) {
    free_bytes(s_line);
  }
  s_line = bigger;
  s_line_size = size;
  return true;
}

// Line editing is Enter and Backspace; the terminal is in raw mode under
// QEMU, so Enter arrives as '\r'. Returns when `shutdown` is entered.
void console_loop() {
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
        s_line[len] = '\0';
        if (len > 0 && !execute(s_line)) {
          return;
        }
        len = 0;
        out("SignetOS> ");
      } else if (c == 0x7f || c == 0x08) {  // DEL or BS
        if (len > 0) {
          len -= 1;
          out("\b \b");
        }
      } else if (c >= 0x20 && c < 0x7f && line_room(len)) {
        s_line[len++] = c;
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

  // The file system. Anything missing turns the file commands off.
  s_roots[ROOT_HOME].handle = rw[SLOT_HOME];
  s_roots[ROOT_BIN].handle = rw[SLOT_BIN];
  s_roots[ROOT_APPS].handle = rw[SLOT_APPS];
  s_roots[ROOT_DISK].handle = rw[SLOT_DISK];
  s_fs_ready = true;
  for (const Root& root : s_roots) {
    const OType type =
        &root == &s_roots[ROOT_DISK] ? OType::FsQuota : OType::FsDir;
    s_fs_ready = s_fs_ready && sealing::is_sealed_as(type, root.handle);
  }
  for (uint32_t i = 0; i < init::FS_CALLS; ++i) {
    s_fs[i] = lookup_name(gate_invoke, naming_lookup, init::FS_CALL_NAMES[i]);
    s_fs_ready = s_fs_ready && capability_is_valid(s_fs[i]);
  }
  out(s_fs_ready
          ? "[shell]    fs.* resolved by name; /home, /bin, /apps and the disk "
            "quota received\n"
          : "[shell]    WARNING: no file system (fs.* or a handle is missing); "
            "file commands disabled\n");

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
  s_gate_thread_kill = rw[SLOT_SYS_THREAD_KILL];
  s_gate_revoke_query = rw[SLOT_SYS_REVOKE_QUERY];
  s_gate_revoke_start = rw[SLOT_SYS_REVOKE_START];
  s_run_ready = sealing::is_sealed_as(OType::EntryPoint, s_gate_thread_kill) &&
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
                sealing::is_sealed_as(OType::EntryPoint, gate_comp_destroy);
  if (!s_run_ready) {
    out("[shell]    WARNING: the /bin view or a kernel entry `run` needs is "
        "missing; programs disabled\n");
  }
  size_t service_count = 0;
  s_services[service_count++] = launch::Service{"uart", s_uart};
  for (uint32_t i = 0; i < init::FS_CALLS; ++i) {
    s_services[service_count++] =
        launch::Service{init::FS_CALL_NAMES[i], s_fs[i]};
  }
  s_services[service_count++] = launch::Service{"seal.mint", s_seal_mint};
  s_services[service_count++] = launch::Service{"seal.derive", s_seal_derive};
  s_services[service_count++] = launch::Service{"seal.seal", s_seal_seal};
  s_services[service_count++] = launch::Service{"seal.unseal", s_seal_unseal};
  launch::Starter& starter = s_starter;
  starter.invoke = gate_invoke;
  starter.self = self_comp;
  starter.vm_quota = vm_quota;
  starter.thread_quota = thread_quota;
  starter.sched_quota = sched_quota;
  starter.vm_allocate = gate_vm_alloc;
  starter.vm_deallocate = gate_vm_dealloc;
  starter.quota_vm_derive = gate_q_derive;
  starter.quota_vm_destroy = gate_q_destroy;
  starter.compartment_create = gate_comp_create;
  starter.compartment_destroy = gate_comp_destroy;
  starter.thread_create = gate_thread_create;
  starter.thread_kill = s_gate_thread_kill;
  starter.revoke_query = s_gate_revoke_query;
  starter.revoke_start = s_gate_revoke_start;
  starter.sched_block = s_sched_block;
  starter.sched_derive = s_sched_derive;
  starter.sched_query = s_sched_query;
  starter.sched_destroy = s_sched_destroy;
  starter.sched_register = s_sched_register;
  starter.uart = uart_sentry;
  for (uint32_t i = 0; i < init::FS_CALLS; ++i) {
    starter.fs[i] = s_fs[i];
  }
  starter.bin = s_roots[ROOT_BIN].handle;
  starter.apps = s_roots[ROOT_APPS].handle;
  starter.disk = s_roots[ROOT_DISK].handle;
  starter.services = s_services;
  starter.service_count = service_count;
  starter.ticks_per_us = s_ticks_per_us;

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
  // The sweeper's thread, or the machine would never stop (sweeper.cpp).
  if (capability_is_valid(rw[SLOT_SWEEPER_STOP])) {
    invoke<int64_t>(gate_invoke, rw[SLOT_SWEEPER_STOP]);
  }
#if defined(SIGNETOS_PAGING)
  // The pager's thread too, or the machine would never stop (blk.cpp, PAGING).
  if (capability_is_valid(rw[SLOT_PAGING_STOP])) {
    invoke<int64_t>(gate_invoke, rw[SLOT_PAGING_STOP]);
  }
#endif
  // Returning exits the shell thread. With nothing left registered, the
  // scheduler's dispatcher exits too and the kernel's host loop returns.
  return 0;
}

}  // namespace signetos::user
