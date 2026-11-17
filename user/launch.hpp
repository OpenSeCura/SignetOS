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

// launch.hpp - Starting a program, for whatever starts programs
//
// A program gets what its manifest asks for, all of it out of what the
// starter holds (`Starter`):
//   - its own directory /apps/<id>/own and its own disk quota <id> (under the
//     starter's), made the first time, the quota with the size the manifest
//     asks for (at most DISK_MAX), and reopened after;
//   - for each other DIR or FILE request: what was picked for this run, else
//     the link /apps/<id>/<request>, else nothing;
//   - its VM quota, a CPU node, and the services the starter offers by name.
//
// IDs: /apps/list has a line "<name> <id>" per program. A program gets an ID
// the first time it needs one, and keeps it whatever it is called.
//
// When the program ends, everything it was given is closed or destroyed. Its
// files, quota and links stay, so the next start gives it the same again.

#pragma once

#include "runtime.hpp"

namespace signetos::user::launch {

// A service the starter offers programs, by the name it is published under.
struct Service {
  const char* name;
  Capability entry;
};

// What the starter holds. A program can reach no further than this.
struct Starter {
  Capability invoke;        // compartment_invoke
  Capability self;          // the starter's compartment
  Capability vm_quota;      // images, programs' VM quotas, CPU nodes, handles
  Capability thread_quota;  // programs' threads
  Capability sched_quota;   // quota_sched node programs' nodes come out of
  Capability vm_allocate;   // kernel entries
  Capability vm_deallocate;
  Capability quota_vm_derive;
  Capability quota_vm_destroy;
  Capability compartment_create;
  Capability compartment_destroy;
  Capability thread_create;
  Capability thread_kill;
  Capability revoke_query;
  Capability sched_block;  // scheduler entries
  Capability sched_derive;
  Capability sched_query;
  Capability sched_destroy;
  Capability sched_register;
  Capability uart;
  Capability fs[init::FS_CALLS];
  Capability bin;   // FsDir: program images, <name>.bin
  Capability apps;  // FsDir: /apps
  Capability disk;  // FsQuota: programs' quotas come out of it
  const Service* services;
  size_t service_count;
  uint64_t ticks_per_us;
};

// What was picked for request `name`, for one run.
struct Pick {
  const char* name;
  Capability handle;
};

constexpr int64_t NOT_RUN = -1;  // a program's status if it never ran

constexpr size_t VM_DEFAULT = 64 * 1024;    // for a manifest asking for 0
constexpr size_t VM_MAX = 128 * 1024;       // the most a program may ask
constexpr uint64_t DISK_MAX = 1024 * 1024;  // the most a program may ask
constexpr size_t STACK_BYTES = 64 * 1024;
constexpr uint32_t BUDGET_US = 20'000;  // CPU: at most this per PERIOD_US
constexpr uint32_t PERIOD_US = 100'000;
constexpr uint32_t PERIOD_MIN_US = 1'000;  // the periods a manifest may ask
constexpr uint32_t PERIOD_MAX_US = 1'000'000;
constexpr uint64_t POLL_US = 5'000;          // how often to look if it ended
constexpr size_t ID_MAX = 21;                // a decimal ID and its NUL
inline constexpr const char* LIST = "list";  // /apps/list
inline constexpr const char* OWN = "own";    // /apps/<id>/own

// In .bss, not on a stack: the kernel refuses seeds that overlap the stack,
// and takes the request as a global capability.
inline Capability s_seeds[init::MANIFEST_MAX];
inline init::AppRequest s_app_request;

// --- Small helpers
// -------------------------------------------------------------

inline void out(const Starter& starter, const char* msg) {
  print(starter.invoke, starter.uart, msg);
}

inline void out_dec(const Starter& starter, const char* prefix, uint64_t value,
                    const char* suffix) {
  print_dec(starter.invoke, starter.uart, prefix, value, suffix);
}

inline bool same_text(const char* a, const char* b) {
  while (*a != '\0' && *a == *b) {
    ++a;
    ++b;
  }
  return *a == *b;
}

// A request names one link in /apps/<id>: a single name, not "own".
inline bool is_request_name(const char* name) {
  if (name[0] == '\0' || same_text(name, OWN)) {
    return false;
  }
  for (const char* cursor = name; *cursor != '\0'; ++cursor) {
    if (*cursor == '/') {
      return false;
    }
  }
  return true;
}

template <typename T>
Capability bounded(T* object) {
  return capability_set_bounds(reinterpret_cast<Capability>(object), sizeof(T));
}

template <typename R = int64_t, typename... A>
R fs(const Starter& starter, uint32_t call, A... args) {
  return invoke<R>(starter.invoke, starter.fs[call], args...);
}

// FS_OK if `handle` is a handle, else the error it carries.
inline int64_t status_of(Capability handle) {
  return capability_is_valid(handle)
             ? init::FS_OK
             : init::cap_error(handle, init::FS_INVALID);
}

inline const char* status_name(int64_t status) {
  switch (status) {
    case init::FS_OK:
      return "OK";
    case init::FS_BAD_REQUEST:
      return "bad request";
    case init::FS_INVALID:
      return "no such handle";
    case init::FS_PERMISSION:
      return "permission denied";
    case init::FS_QUOTA:
      return "quota exceeded";
    case init::FS_NO_MEMORY:
      return "out of memory";
    case init::FS_NOT_FOUND:
      return "not found";
    case init::FS_EXISTS:
      return "already exists";
    case init::FS_FROZEN:
      return "frozen";
    case init::FS_TOO_LARGE:
      return "file too large";
    case init::FS_IO_ERROR:
      return "I/O error";
    case init::FS_DISK_FULL:
      return "disk full";
    case init::FS_NOT_MOUNTED:
      return "not mounted";
    case init::FS_NOT_DIR:
      return "not a directory";
    case init::FS_IS_DIR:
      return "is a directory";
    case init::FS_BUSY:
      return "busy";
    case init::FS_IN_USE:
      return "in use";
    default:
      return "unknown status";
  }
}

// A handle, closed when this goes out of scope.
struct ScopedHandle {
  const Starter& starter;
  Capability handle = nullptr;
  explicit ScopedHandle(const Starter& starter) : starter(starter) {}
  ScopedHandle(const ScopedHandle&) = delete;
  ScopedHandle& operator=(const ScopedHandle&) = delete;
  ~ScopedHandle() {
    if (capability_is_valid(handle)) {
      fs(starter, init::FS_CALL_CLOSE, handle);
    }
  }
};

template <typename Attempt, typename Ok>
auto with_reclaim(const Starter& starter, Attempt attempt, Ok ok) {
  auto result = attempt();
  if (ok(result) || !capability_is_valid(starter.revoke_query)) {
    return result;
  }
  using FnQuery = decltype(&sys_revoke_query);
  const uint64_t seen =
      syscall::call<FnQuery>(starter.invoke, starter.revoke_query);
  result = attempt();
  if (ok(result)) {
    return result;
  }
  revoke_wait(starter.invoke, starter.revoke_query, starter.sched_block,
              seen + 1);
  return attempt();
}

// Frees an allocation of the starter's; null is fine.
inline void release(const Starter& starter, Capability memory) {
  using FnDealloc = decltype(&sys_vm_deallocate);
  if (capability_is_valid(memory)) {
    syscall::call<FnDealloc>(starter.invoke, starter.vm_deallocate,
                             starter.self, starter.vm_quota, memory);
  }
}

// Reads `path` under `dir` into fresh zeroed pages, NUL-terminated. Null if it
// cannot, with the status in `*error`.
inline Capability read_all(const Starter& starter, Capability dir,
                           const char* path, uint64_t* size, int64_t* error) {
  using FnAlloc = decltype(&sys_vm_allocate);
  ScopedHandle file(starter);
  file.handle = fs<Capability>(starter, init::FS_CALL_OPEN, dir, ro_str(path),
                               init::FS_READ, starter.vm_quota);
  init::FsStat stat{};
  *error = status_of(file.handle);
  if (*error == init::FS_OK) {
    *error = fs(starter, init::FS_CALL_STAT, file.handle, bounded(&stat));
  }
  Capability memory = nullptr;
  if (*error == init::FS_OK) {
    const size_t bytes =
        (static_cast<size_t>(stat.size) + vm::PAGE_SIZE) & ~(vm::PAGE_SIZE - 1);
    memory = with_reclaim(
        starter,
        [&] {
          return syscall::call<FnAlloc>(starter.invoke, starter.vm_allocate,
                                        starter.self, starter.vm_quota, bytes,
                                        0);
        },
        [](Capability result) { return capability_is_valid(result); });
    *error = capability_is_valid(memory) ? init::FS_OK : init::FS_NO_MEMORY;
  }
  if (*error == init::FS_OK) {
    const int64_t bytes_read =
        fs(starter, init::FS_CALL_READ, file.handle, memory, 0ULL, stat.size);
    *error = bytes_read < 0 ? bytes_read
             : static_cast<uint64_t>(bytes_read) == stat.size
                 ? init::FS_OK
                 : init::FS_IO_ERROR;
  }
  if (*error != init::FS_OK) {
    release(starter, memory);
    return nullptr;
  }
  *size = stat.size;
  return memory;
}

// Opens `name` under `dir` (a directory or quota) with `rights`, paid by
// `memory_quota`; if it is not there, makes it with `make` first.
template <typename Make>
Capability open_or_make(const Starter& starter, Capability dir,
                        const char* name, uint32_t rights,
                        Capability memory_quota, Make make) {
  Capability handle = fs<Capability>(starter, init::FS_CALL_OPEN, dir,
                                     ro_str(name), rights, memory_quota);
  if (init::cap_error(handle, 0) == init::FS_NOT_FOUND) {
    const Capability made = make();
    if (!capability_is_valid(made)) {
      return made;
    }
    fs(starter, init::FS_CALL_CLOSE, made);
    handle = fs<Capability>(starter, init::FS_CALL_OPEN, dir, ro_str(name),
                            rights, memory_quota);
  }
  return handle;
}

// Zeroed memory of the starter's, `bytes` of it at least, given back when
// this goes out of scope; `text` is null if there was none.
struct Scratch {
  const Starter& starter;
  char* text = nullptr;
  Scratch(const Starter& starter, size_t bytes) : starter(starter) {
    using FnAlloc = decltype(&sys_vm_allocate);
    const size_t size = (bytes + vm::PAGE_SIZE - 1) & ~(vm::PAGE_SIZE - 1);
    const Capability memory = with_reclaim(
        starter,
        [&] {
          return syscall::call<FnAlloc>(starter.invoke, starter.vm_allocate,
                                        starter.self, starter.vm_quota, size,
                                        0);
        },
        [](Capability result) { return capability_is_valid(result); });
    text = capability_is_valid(memory) ? static_cast<char*>(memory) : nullptr;
  }
  Scratch(const Scratch&) = delete;
  Scratch& operator=(const Scratch&) = delete;
  ~Scratch() { release(starter, text); }
};

inline size_t text_length(const char* text) {
  size_t length = 0;
  while (text[length] != '\0') {
    ++length;
  }
  return length;
}

// The `length` bytes at `text`, and a NUL, into `out`.
inline void copy_text(char* out, const char* text, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    out[i] = text[i];
  }
  out[length] = '\0';
}

inline bool ends_in_bin(const char* name, size_t length) {
  return length > 4 && same_text(name + length - 4, ".bin");
}

// `name` plus ".bin", unless it has it, into `file` (text_length(name) + 5
// bytes).
inline void image_name(const char* name, char* file) {
  const size_t length = text_length(name);
  const char* extension = ends_in_bin(name, length) ? "" : ".bin";
  copy_text(file, name, length);
  copy_text(file + length, extension, text_length(extension));
}

// `name` without ".bin", into `program` (text_length(name) + 1 bytes).
inline void program_name(const char* name, char* program) {
  const size_t length = text_length(name);
  copy_text(program, name, ends_in_bin(name, length) ? length - 4 : length);
}

// --- IDs: /apps/list
// -----------------------------------------------------------

// The next "<name> <id>" line at `cursor`: the name left where it is,
// `*length` bytes at `*name`, and the ID copied into `id`.
inline bool next_entry(const char*& cursor, const char** name, size_t* length,
                       char* id) {
  while (*cursor == '\n' || *cursor == ' ') {
    ++cursor;
  }
  if (*cursor == '\0') {
    return false;
  }
  *name = cursor;
  while (*cursor > ' ') {
    ++cursor;
  }
  *length = static_cast<size_t>(cursor - *name);
  while (*cursor == ' ') {
    ++cursor;
  }
  size_t id_length = 0;
  for (; *cursor > ' '; ++cursor) {
    if (id_length + 1 < ID_MAX) {
      id[id_length++] = *cursor;
    }
  }
  id[id_length] = '\0';
  while (*cursor != '\0' && *cursor++ != '\n') {
  }
  return true;
}

// Whether the `length` bytes at `word` are `text`.
inline bool same_word(const char* word, size_t length, const char* text) {
  for (size_t i = 0; i < length; ++i) {
    if (text[i] != word[i]) {  // a NUL in `text` differs from any byte of `word`
      return false;
    }
  }
  return text[length] == '\0';
}

inline uint64_t parse_number(const char* text) {
  uint64_t value = 0;
  for (; *text >= '0' && *text <= '9'; ++text) {
    value = (value * 10) + static_cast<uint64_t>(*text - '0');
  }
  return value;
}

inline void format_decimal(uint64_t value, char* text) {
  char digits[ID_MAX];
  size_t position = ID_MAX - 1;
  digits[position] = '\0';
  do {
    digits[--position] = static_cast<char>('0' + (value % 10));
    value /= 10;
  } while (value != 0 && position > 0);
  for (size_t i = 0; (text[i] = digits[position + i]) != '\0'; ++i) {
  }
}

// The ID of `program`, into `id`. False if it has none.
inline bool find_id(const Starter& starter, const char* program, char* id) {
  uint64_t size = 0;
  int64_t error = init::FS_OK;
  const Capability text = read_all(starter, starter.apps, LIST, &size, &error);
  if (text == nullptr) {
    return false;
  }
  bool found = false;
  const char* name = nullptr;
  size_t length = 0;
  char entry_id[ID_MAX];
  for (const char* cursor = static_cast<const char*>(text);
       !found && next_entry(cursor, &name, &length, entry_id);) {
    found = same_word(name, length, program);
  }
  if (found) {
    for (size_t i = 0; (id[i] = entry_id[i]) != '\0'; ++i) {
    }
  }
  release(starter, text);
  return found;
}

// Gives `program` an ID: one above any in the list, and not the name of
// anything left in /apps or under the starter's quota.
inline int64_t add_id(const Starter& starter, const char* program, char* id) {
  uint64_t size = 0;
  int64_t error = init::FS_OK;
  const Capability text = read_all(starter, starter.apps, LIST, &size, &error);
  if (text == nullptr && error != init::FS_NOT_FOUND) {
    return error;
  }
  uint64_t next = 1;
  const char* name = nullptr;
  size_t name_length = 0;
  char entry_id[ID_MAX];
  for (const char* cursor = static_cast<const char*>(text);
       text != nullptr && next_entry(cursor, &name, &name_length, entry_id);) {
    next = parse_number(entry_id) >= next ? parse_number(entry_id) + 1 : next;
  }
  release(starter, text);
  for (;; ++next) {
    format_decimal(next, id);
    ScopedHandle dir(starter);
    ScopedHandle quota(starter);
    dir.handle = fs<Capability>(starter, init::FS_CALL_OPEN, starter.apps,
                                ro_str(id), 0u, starter.vm_quota);
    quota.handle = fs<Capability>(starter, init::FS_CALL_OPEN, starter.disk,
                                  ro_str(id), 0u, starter.vm_quota);
    if (status_of(dir.handle) == init::FS_NOT_FOUND &&
        status_of(quota.handle) == init::FS_NOT_FOUND) {
      break;
    }
  }
  // One write, so the line goes in whole.
  const size_t program_length = text_length(program);
  Scratch line(starter, program_length + ID_MAX + 2);
  if (line.text == nullptr) {
    return init::FS_NO_MEMORY;
  }
  copy_text(line.text, program, program_length);
  size_t length = program_length;
  line.text[length++] = ' ';
  for (const char* cursor = id; *cursor != '\0'; ++cursor) {
    line.text[length++] = *cursor;
  }
  line.text[length++] = '\n';
  ScopedHandle list(starter);
  list.handle = open_or_make(
      starter, starter.apps, LIST, init::FS_ADD, starter.vm_quota, [&] {
        return fs<Capability>(starter, init::FS_CALL_CREATE, starter.apps,
                              ro_str(LIST), starter.disk, 0u, starter.vm_quota);
      });
  const int64_t status = status_of(list.handle);
  if (status != init::FS_OK) {
    return status;
  }
  const int64_t written =
      fs(starter, init::FS_CALL_WRITE, list.handle,
         capability_set_bounds(reinterpret_cast<Capability>(line.text), length),
         init::FS_APPEND, uint64_t{length}, starter.disk);
  return written < 0 ? written : init::FS_OK;
}

// /apps/<id>, made the first time and paid for by the starter.
inline Capability open_app_dir(const Starter& starter, const char* id) {
  return open_or_make(starter, starter.apps, id, init::FS_ALL | init::FS_LINK,
                      starter.vm_quota, [&] {
                        return fs<Capability>(starter, init::FS_CALL_CREATE,
                                              starter.apps, ro_str(id),
                                              starter.disk, init::FS_CREATE_DIR,
                                              starter.vm_quota);
                      });
}

// --- What a program gets
// ---------------------------------------------------------

// Step 3 for a DIR, FILE or QUOTA_DISK entry, paid for by `memory_quota`: a
// handle, or a status. `*source` says where it came from.
inline Capability open_fs_handle(const Starter& starter,
                                 const init::ManifestEntry& entry,
                                 Capability app_dir, const char* id,
                                 Capability memory_quota, const Pick* picks,
                                 size_t pick_count, const char** source) {
  if ((entry.flags & init::MANIFEST_OWN) != 0) {
    if (!capability_is_valid(app_dir)) {
      return init::status_cap(init::FS_NOT_FOUND);
    }
    if (entry.kind == init::MANIFEST_DIR) {
      return open_or_make(
          starter, app_dir, OWN, entry.perms & init::FS_ALL, memory_quota, [&] {
            return fs<Capability>(starter, init::FS_CALL_CREATE, app_dir,
                                  ro_str(OWN), starter.disk,
                                  init::FS_CREATE_DIR, starter.vm_quota);
          });
    }
    if (entry.kind == init::MANIFEST_QUOTA_DISK) {
      const uint64_t bytes = entry.amount > DISK_MAX ? DISK_MAX : entry.amount;
      return open_or_make(
          starter, starter.disk, id,
          entry.perms & (init::FS_READ | init::FS_ADD), memory_quota, [&] {
            return fs<Capability>(starter, init::FS_CALL_QUOTA, starter.disk,
                                  ro_str(id), bytes, starter.vm_quota);
          });
    }
    return nullptr;
  }
  if (entry.kind == init::MANIFEST_QUOTA_DISK) {
    return nullptr;  // a program only gets its own
  }
  if (!is_request_name(entry.name)) {
    return init::status_cap(init::FS_BAD_REQUEST);
  }
  const uint32_t rights = entry.perms & init::FS_ALL;
  Capability handle = nullptr;
  for (size_t i = 0; i < pick_count && handle == nullptr; ++i) {
    if (same_text(picks[i].name, entry.name)) {
      handle = fs<Capability>(starter, init::FS_CALL_OPEN, picks[i].handle,
                              ro_str(""), rights, memory_quota);
      *source = "picked";
    }
  }
  if (handle == nullptr && capability_is_valid(app_dir)) {
    handle = fs<Capability>(starter, init::FS_CALL_OPEN, app_dir,
                            ro_str(entry.name), rights, memory_quota);
    *source = "linked";
    if (init::cap_error(handle, 0) == init::FS_NOT_FOUND) {
      handle = nullptr;
      *source = nullptr;
    }
  }
  const OType expected_type =
      entry.kind == init::MANIFEST_DIR ? OType::FsDir : OType::FsFile;
  if (capability_is_valid(handle) &&
      !sealing::is_sealed_as(expected_type, handle)) {
    fs(starter, init::FS_CALL_CLOSE, handle);
    return init::status_cap(entry.kind == init::MANIFEST_DIR ? init::FS_NOT_DIR
                                                             : init::FS_IS_DIR);
  }
  return handle;
}

// Step 3: fills `s_seeds` from the manifest, and `*app_dir` with /apps/<id> if
// the program has one; it must stay open while the program runs. False if a
// REQUIRED entry was not met. Prints the grants on one line.
inline bool fill_seeds(const Starter& starter, const char* program,
                       const init::Manifest& manifest, Capability quota,
                       Capability node, const Pick* picks, size_t pick_count,
                       Capability* app_dir) {
  bool any_own = false;
  bool any_request = false;
  for (uint32_t i = 0; i < manifest.count; ++i) {
    const init::ManifestEntry& entry = manifest.entries[i];
    any_own = any_own || (init::manifest_is_fs(entry.kind) &&
                          (entry.flags & init::MANIFEST_OWN) != 0);
    any_request = any_request || entry.kind == init::MANIFEST_DIR ||
                  entry.kind == init::MANIFEST_FILE;
  }
  char id[ID_MAX];
  id[0] = '\0';
  int64_t id_status =
      find_id(starter, program, id) ? init::FS_OK : init::FS_NOT_FOUND;
  if (id_status != init::FS_OK && any_own) {
    id_status = add_id(starter, program, id);
  }
  if (id_status == init::FS_OK && (any_own || any_request)) {
    *app_dir = open_app_dir(starter, id);
  }
  out(starter, "[run]      ");
  out(starter, program);
  if (id_status == init::FS_OK) {
    out(starter, " (id ");
    out(starter, id);
    out(starter, ")");
  }
  out(starter, " gets:");
  bool ok = true;
  for (uint32_t i = 0; i < manifest.count; ++i) {
    const init::ManifestEntry& entry = manifest.entries[i];
    const char* source = nullptr;
    Capability seed = nullptr;
    switch (entry.kind) {
      case init::MANIFEST_SYSCALL:
        if (entry.count ==
            static_cast<uint32_t>(syscall::Id::compartment_invoke)) {
          seed = starter.invoke;
        }
        break;
      case init::MANIFEST_SERVICE:
        for (size_t k = 0; k < starter.service_count; ++k) {
          if (same_text(entry.name, starter.services[k].name)) {
            seed = starter.services[k].entry;
          }
        }
        break;
      case init::MANIFEST_DIR:
      case init::MANIFEST_FILE:
      case init::MANIFEST_QUOTA_DISK:
        seed = open_fs_handle(starter, entry, *app_dir, id, quota, picks,
                              pick_count, &source);
        break;
      case init::MANIFEST_QUOTA_VM:
        seed = quota;
        break;
      case init::MANIFEST_QUOTA_SCHED:
        seed = node;
        break;
      default:
        break;
    }
    s_seeds[i] = capability_is_valid(seed) ? seed : nullptr;
    out(starter, " ");
    print_manifest_entry(starter.invoke, starter.uart, entry);
    if (capability_is_valid(seed) && entry.kind == init::MANIFEST_QUOTA_DISK) {
      init::FsStat stat{};
      if (fs(starter, init::FS_CALL_STAT, seed, bounded(&stat)) ==
          init::FS_OK) {
        out_dec(starter, "(", stat.used / 1024, " of ");
        out_dec(starter, "", stat.size / 1024, " KiB used)");
      }
    }
    if (source != nullptr) {
      out(starter, "(");
      out(starter, source);
      out(starter, ")");
    }
    if (!capability_is_valid(seed)) {
      const int64_t error = init::cap_error(seed, init::FS_OK);
      if (error != init::FS_OK && error != init::FS_NOT_FOUND) {
        out(starter, "(");
        out(starter, status_name(error));
        out(starter, ")");
      }
      const bool required = (entry.flags & init::MANIFEST_REQUIRED) != 0;
      out(starter, required ? "=REFUSED" : "=none");
      ok = ok && !required;
    }
  }
  out(starter, "\n");
  return ok;
}

// A CPU node for the program: what the first QUOTA_SCHED entry of its manifest
// asks for, held to at most BUDGET_US per PERIOD_US and never above the
// interactive class; exactly that, interactive, if it asks for none (or 0).
inline Capability cpu_node(const Starter& starter,
                           const init::Manifest& manifest) {
  uint32_t period = PERIOD_US;
  uint64_t budget = BUDGET_US;
  uint8_t priority = init::PRIORITY_INTERACTIVE;
  for (uint32_t i = 0; i < manifest.count; ++i) {
    const init::ManifestEntry& entry = manifest.entries[i];
    if (entry.kind != init::MANIFEST_QUOTA_SCHED) {
      continue;
    }
    if (entry.count != 0) {
      period = entry.count < PERIOD_MIN_US   ? PERIOD_MIN_US
               : entry.count > PERIOD_MAX_US ? PERIOD_MAX_US
                                             : entry.count;
    }
    const uint64_t max_budget =
        static_cast<uint64_t>(BUDGET_US) * period / PERIOD_US;
    budget = (entry.amount == 0 || entry.amount > max_budget) ? max_budget
                                                              : entry.amount;
    if (entry.param >
        priority) {  // a lower class; anything else stays interactive
      priority = entry.param > init::PRIORITY_BATCH
                     ? init::PRIORITY_BATCH
                     : static_cast<uint8_t>(entry.param);
    }
    break;
  }
  init::SchedDeriveRequest request{};
  request.parent = starter.sched_quota;
  request.node_funding = starter.vm_quota;
  request.budget_us = static_cast<uint32_t>(budget);
  request.period_us = period;
  request.term_us = init::SCHED_REVOCABLE;
  request.priority_class = priority;
  with_reclaim(
      starter,
      [&] {
        request.status = init::SCHED_BAD_REQUEST;
        invoke<int64_t>(starter.invoke, starter.sched_derive,
                        bounded(&request));
        return request.status;
      },
      [](int64_t status) { return status != init::SCHED_NO_MEMORY; });
  return request.status == init::SCHED_OK ? request.out_quota : nullptr;
}

// Starts the program's thread at `entry_point` with `s_app_request`, on
// `node`. False if it could not, in which case nothing of it is left running.
inline bool start_thread(const Starter& starter, Capability entry_point,
                         Capability node) {
  using FnThreadCreate = decltype(&sys_thread_create);
  using FnThreadKill = decltype(&sys_thread_kill);
  const Capability thread = with_reclaim(
      starter,
      [&] {
        return syscall::call<FnThreadCreate>(
            starter.invoke, starter.thread_create, starter.thread_quota,
            STACK_BYTES, entry_point, bounded(&s_app_request));
      },
      [](Capability result) {
        return sealing::is_sealed_as(OType::Thread, result);
      });
  if (!sealing::is_sealed_as(OType::Thread, thread)) {
    out(starter, "[run]      no thread memory left for a program\n");
    return false;
  }
  if (invoke<int64_t>(starter.invoke, starter.sched_register, thread, node) <=
      0) {
    // Never dispatched, so never inside anything: safe to end here.
    syscall::call<FnThreadKill>(starter.invoke, starter.thread_kill, thread);
    out(starter,
        "[run]      the scheduler would not take the program's thread\n");
    return false;
  }
  return true;
}

// Sleeps until the program's thread has ended -- nothing is registered on its
// node any more -- then destroys the node.
inline bool wait_thread(const Starter& starter, Capability node) {
  int64_t threads = 0;
  do {
    invoke<int64_t>(starter.invoke, starter.sched_block, POLL_US);
    init::SchedQueryRequest request{};
    request.status = init::SCHED_BAD_REQUEST;
    invoke<int64_t>(starter.invoke, starter.sched_query, node,
                    bounded(&request));
    threads = request.status == init::SCHED_OK
                  ? static_cast<int64_t>(request.threads)
                  : request.status;
  } while (threads > 0);
  const int64_t status =
      threads == 0 ? invoke<int64_t>(starter.invoke, starter.sched_destroy,
                                     starter.sched_quota, node)
                   : threads;
  if (status != init::SCHED_OK) {
    out_dec(starter,
            "[run]      WARNING: the program's CPU node would not go, status -",
            static_cast<uint64_t>(-status), "\n");
    return false;
  }
  return true;
}

// --- Starting one
// ----------------------------------------------------------------

// Runs program `name` (<name>.bin in `bin`) with `picks` for this run, and
// waits for it to end. False if it could not be started; `*status` is what it
// returned.
inline bool run(const Starter& starter, const char* name, const Pick* picks,
                size_t pick_count, const char* args, int64_t* status) {
  using FnQuotaDerive = decltype(&sys_quota_vm_derive);
  using FnQuotaDestroy = decltype(&sys_quota_vm_destroy);
  using FnCompDestroy = decltype(&sys_compartment_destroy);
  *status = NOT_RUN;

  // 1. The program and its manifest.
  Scratch file_text(starter, text_length(name) + 5);
  Scratch program_text(starter, text_length(name) + 1);
  if (file_text.text == nullptr || program_text.text == nullptr) {
    out(starter, "[run]      no memory left for the program's name\n");
    return false;
  }
  char* const file = file_text.text;
  char* const program = program_text.text;
  image_name(name, file);
  program_name(name, program);
  uint64_t size = 0;
  int64_t error = init::FS_OK;
  const Capability image = read_all(starter, starter.bin, file, &size, &error);
  bool ok = capability_is_valid(image);
  if (!ok) {
    out(starter, "[run]      /bin/");
    out(starter, file);
    out(starter, ": ");
    out(starter, status_name(error));
    out(starter, "\n");
  }
  init::Manifest manifest{};
  if (ok) {
    const init::CompartmentImageHeader* header = init::image_header(image);
    ok = header != nullptr && init::manifest_of(image, header, &manifest);
    if (!ok) {
      out(starter,
          "[run]      not a program (no header, or a malformed manifest)\n");
    }
  }
  for (size_t i = 0; ok && i < pick_count; ++i) {
    bool known = false;
    for (uint32_t k = 0; k < manifest.count; ++k) {
      const init::ManifestEntry& entry = manifest.entries[k];
      known = known || ((entry.kind == init::MANIFEST_DIR ||
                         entry.kind == init::MANIFEST_FILE) &&
                        (entry.flags & init::MANIFEST_OWN) == 0 &&
                        same_text(entry.name, picks[i].name));
    }
    if (!known) {
      out(starter, "[run]      ");
      out(starter, program);
      out(starter, " asks for nothing called ");
      out(starter, picks[i].name);
      out(starter, "\n");
      ok = false;
    }
  }

  // 2. Its VM quota, and the CPU node its thread runs under.
  Capability quota = nullptr;
  if (ok) {
    size_t vm_bytes = manifest.vm_bytes == 0
                          ? VM_DEFAULT
                          : static_cast<size_t>(manifest.vm_bytes);
    vm_bytes = vm_bytes > VM_MAX ? VM_MAX : vm_bytes;
    quota = with_reclaim(
        starter,
        [&] {
          return syscall::call<FnQuotaDerive>(
              starter.invoke, starter.quota_vm_derive, starter.vm_quota,
              vm_bytes, perms::Load | perms::Store);
        },
        [](Capability result) {
          return sealing::is_sealed_as(OType::QuotaVm, result);
        });
    ok = sealing::is_sealed_as(OType::QuotaVm, quota);
    if (!ok) {
      out(starter, "[run]      no VM quota left for a program\n");
    }
  }
  Capability node = nullptr;
  if (ok) {
    node = cpu_node(starter, manifest);
    ok = capability_is_valid(node);
    if (!ok) {
      out(starter, "[run]      no CPU bandwidth left for a program\n");
    }
  }

  // 3. What it gets.
  ScopedHandle app_dir(starter);
  if (ok) {
    ok = fill_seeds(starter, program, manifest, quota, node, picks, pick_count,
                    &app_dir.handle);
    if (!ok) {
      out(starter, "[run]      ");
      out(starter, program);
      out(starter, " needs what it was not given; not started\n");
    }
  }

  // 4. Its compartment. The seeds are all it will ever hold. Its memory may
  //    go to swap (vm.hpp, PAGING, WHAT MUST NOT WAIT).
  Capability compartment = nullptr;
  Capability entry_point = nullptr;
  if (ok) {
    const Capability seeds =
        manifest.count == 0
            ? nullptr
            : capability_set_bounds(
                  reinterpret_cast<Capability>(&s_seeds[0]),
                  static_cast<size_t>(manifest.count) * sizeof(Capability));
    ok = create_compartment(starter.invoke, starter.compartment_create,
                            starter.compartment_destroy, quota, seeds, image,
                            COMPARTMENT_PAGEABLE, &compartment, &entry_point);
    if (!ok) {
      out(starter, "[run]      not a program (the image was refused)\n");
    }
  }

  // 5. Run it on a thread of its own, and sleep until that thread has ended.
  if (ok) {
    size_t i = 0;
    for (; i + 1 < init::APP_ARGS_MAX && args[i] != '\0'; ++i) {
      s_app_request.args[i] = args[i];
    }
    for (; i < init::APP_ARGS_MAX; ++i) {
      s_app_request.args[i] = '\0';
    }
    s_app_request.status = NOT_RUN;
    s_app_request.ticks_per_us = starter.ticks_per_us;
    ok = start_thread(starter, entry_point, node);
  }
  if (ok) {
    ok = wait_thread(starter, node);
    node = nullptr;  // destroyed by the wait, or left as it would not go
    *status = s_app_request.status;
  }
  if (capability_is_valid(node)) {
    invoke<int64_t>(starter.invoke, starter.sched_destroy, starter.sched_quota,
                    node);  // never ran
  }

  // 6. Take it all down, in the reverse order it was built. Its fs handles go
  //    before the VM quota that paid for them.
  if (capability_is_valid(compartment)) {
    syscall::call<FnCompDestroy>(starter.invoke, starter.compartment_destroy,
                                 compartment);
  }
  for (uint32_t i = 0; i < manifest.count; ++i) {
    if (init::manifest_is_fs(manifest.entries[i].kind) &&
        capability_is_valid(s_seeds[i])) {
      fs(starter, init::FS_CALL_CLOSE,
         s_seeds[i]);  // and all opened through it
    }
    s_seeds[i] = nullptr;
  }
  if (capability_is_valid(quota) &&
      syscall::call<FnQuotaDestroy>(starter.invoke, starter.quota_vm_destroy,
                                    quota) != 0) {
    out(starter,
        "[run]      WARNING: the program's VM quota would not destroy\n");
  }
  release(starter, image);

  if (ok) {
    out(starter, "[run]      ");
    out(starter, program);
    if (*status == NOT_RUN) {
      out(starter, " returned without a status\n");
    } else if (*status < 0) {
      out_dec(starter, " exited with status -", static_cast<uint64_t>(-*status),
              "\n");
    } else {
      out_dec(starter, " exited with status ", static_cast<uint64_t>(*status),
              "\n");
    }
  }
  return ok;
}

// --- Linking and resizing
// -----------------------------------------------------------

// `request` of program `name`, from its manifest.
inline int64_t find_request(const Starter& starter, const char* name,
                            const char* request, init::ManifestEntry* found) {
  Scratch file(starter, text_length(name) + 5);
  if (file.text == nullptr) {
    return init::FS_NO_MEMORY;
  }
  image_name(name, file.text);
  uint64_t size = 0;
  int64_t status = init::FS_OK;
  const Capability image =
      read_all(starter, starter.bin, file.text, &size, &status);
  if (image == nullptr) {
    return status;
  }
  init::Manifest manifest{};
  const init::CompartmentImageHeader* header = init::image_header(image);
  status = header != nullptr && init::manifest_of(image, header, &manifest)
               ? init::FS_NOT_FOUND
               : init::FS_BAD_REQUEST;
  for (uint32_t i = 0; i < manifest.count && status == init::FS_NOT_FOUND;
       ++i) {
    const init::ManifestEntry& entry = manifest.entries[i];
    if ((entry.kind == init::MANIFEST_DIR ||
         entry.kind == init::MANIFEST_FILE) &&
        (entry.flags & init::MANIFEST_OWN) == 0 &&
        same_text(entry.name, request)) {
      *found = entry;
      status = init::FS_OK;
    }
  }
  release(starter, image);
  return status;
}

// Gives `target` to `request` of program `name` for good: the link
// /apps/<id>/<request>, paid for by the starter, with the rights the request
// asks for. `target` needs LINK.
inline int64_t link(const Starter& starter, const char* name,
                    const char* request, Capability target) {
  if (!is_request_name(request)) {
    return init::FS_BAD_REQUEST;
  }
  init::ManifestEntry entry;  // filled in when find_request finds it
  int64_t status = find_request(starter, name, request, &entry);
  if (status != init::FS_OK) {
    return status;
  }
  const OType expected_type =
      entry.kind == init::MANIFEST_DIR ? OType::FsDir : OType::FsFile;
  if (!sealing::is_sealed_as(expected_type, target)) {
    return entry.kind == init::MANIFEST_DIR ? init::FS_NOT_DIR
                                            : init::FS_IS_DIR;
  }
  Scratch program(starter, text_length(name) + 1);
  if (program.text == nullptr) {
    return init::FS_NO_MEMORY;
  }
  program_name(name, program.text);
  char id[ID_MAX];
  if (!find_id(starter, program.text, id)) {
    status = add_id(starter, program.text, id);
    if (status != init::FS_OK) {
      return status;
    }
  }
  ScopedHandle app_dir(starter);
  app_dir.handle = open_app_dir(starter, id);
  status = status_of(app_dir.handle);
  return status != init::FS_OK
             ? status
             : fs(starter, init::FS_CALL_LINK, app_dir.handle, ro_str(request),
                  target, entry.perms & init::FS_ALL, starter.disk);
}

// Removes the link for `request` of program `name`.
inline int64_t unlink(const Starter& starter, const char* name,
                      const char* request) {
  Scratch program(starter, text_length(name) + 1);
  if (program.text == nullptr) {
    return init::FS_NO_MEMORY;
  }
  program_name(name, program.text);
  char id[ID_MAX];
  if (same_text(request, OWN) || !find_id(starter, program.text, id)) {
    return init::FS_NOT_FOUND;
  }
  for (const char* cursor = request; *cursor != '\0'; ++cursor) {
    if (*cursor == '/') {
      return init::FS_BAD_REQUEST;
    }
  }
  ScopedHandle app_dir(starter);
  app_dir.handle = fs<Capability>(starter, init::FS_CALL_OPEN, starter.apps,
                                  ro_str(id), init::FS_ALL, starter.vm_quota);
  const int64_t status = status_of(app_dir.handle);
  return status != init::FS_OK ? status
                               : fs(starter, init::FS_CALL_REMOVE,
                                    app_dir.handle, ro_str(request));
}

// Sets program `name`'s own quota to `bytes`: growing takes from the
// starter's, shrinking stops at what it has used.
inline int64_t resize_quota(const Starter& starter, const char* name,
                            uint64_t bytes) {
  Scratch program(starter, text_length(name) + 1);
  if (program.text == nullptr) {
    return init::FS_NO_MEMORY;
  }
  program_name(name, program.text);
  char id[ID_MAX];
  if (!find_id(starter, program.text, id)) {
    return init::FS_NOT_FOUND;
  }
  ScopedHandle quota(starter);
  quota.handle = fs<Capability>(starter, init::FS_CALL_OPEN, starter.disk,
                                ro_str(id), 0u, starter.vm_quota);
  int64_t status =
      status_of(quota.handle);  // made at its first start, not here
  if (status == init::FS_OK) {
    ScopedHandle resized(starter);
    resized.handle = fs<Capability>(starter, init::FS_CALL_QUOTA, starter.disk,
                                    ro_str(id), bytes, starter.vm_quota);
    status = status_of(resized.handle);
  }
  return status;
}

}  // namespace signetos::user::launch
