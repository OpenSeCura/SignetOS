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
 * hello.cpp - A program: a compartment image that lives on the disk
 *
 * Not part of the system. `external/apps/hello.bin` is written to `/bin` on
 * the disk image (`tools/signetfs.py put --dir bin`, see the Makefile); the
 * shell's `run hello [args]` reads it from there, makes a compartment of it,
 * invokes `compartment_main` once with an `AppRequest` (abi.hpp,
 * "Applications") and destroys the compartment when it returns.
 *
 * It holds only what its manifest asks for: its own directory and quota
 * (launch.hpp), and `motd` if one is picked or linked for it. Each run appends a
 * line to `visits.txt` in its directory and prints the count, which survives
 * restarts.
 */

#include "runtime.hpp"

namespace signetos::user {
namespace {

// --- What `hello` asks for (user/manifest.hpp) --------------------------------
// Its own directory and a 64 KiB quota; MOTD, a file, if it is given one.
#define HELLO_MANIFEST(X)                                                  \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)                        \
  M_SERVICE(X, UART_SENTRY, "uart")                                        \
  M_SERVICE(X, FS_OPEN, "fs.open")                                         \
  M_SERVICE(X, FS_CREATE, "fs.create")                                     \
  M_SERVICE(X, FS_READ, "fs.read")                                         \
  M_SERVICE(X, FS_WRITE, "fs.write")                                       \
  M_SERVICE(X, FS_STAT, "fs.stat")                                         \
  M_QUOTA_VM(X, VM_QUOTA)                                                  \
  M_OWN_DIR(X, HOME)                                                       \
  M_OWN_DISK(X, DISK, 64 * 1024)                                           \
  M_FILE(X, MOTD, 0, ::signetos::init::FS_READ, "motd")
SIGNETOS_MANIFEST(HELLO_MANIFEST, 64 * 1024)

Capability s_invoke = nullptr;
Capability s_uart = nullptr;

char s_text[128];  // what goes into the file, and what comes back out

void out(const char* msg) { print(s_invoke, s_uart, msg); }
void out_dec(const char* prefix, uint64_t value, const char* suffix) {
  print_dec(s_invoke, s_uart, prefix, value, suffix);
}
void out_status(const char* what, int64_t status) {
  out(what);
  out_dec(": status -", static_cast<uint64_t>(-status), "\n");
}

// No libc: a string copied by hand.
size_t append(char* dst, size_t length, size_t capacity, const char* src) {
  while (length + 1 < capacity && *src != '\0') {
    dst[length++] = *src++;
  }
  dst[length] = '\0';
  return length;
}

Capability region(void* start, size_t length) {
  return capability_set_bounds(reinterpret_cast<Capability>(start), length);
}

// Reads `file` at `offset` into `s_text`; returns bytes read or an FS_* error.
int64_t read_text(Capability* rw, Capability file, uint64_t offset) {
  const int64_t bytes_read =
      invoke<int64_t>(s_invoke, rw[SLOT_FS_READ], file,
                      region(s_text, sizeof(s_text) - 1), offset,
                      uint64_t{sizeof(s_text) - 1});
  s_text[bytes_read > 0 ? bytes_read : 0] = '\0';
  return bytes_read;
}

// Appends a line to visits.txt, then prints the visit count and quota use.
void record_visit(Capability* rw, const char* args) {
  const Capability home = rw[SLOT_HOME];
  const Capability memory_quota = rw[SLOT_VM_QUOTA];  // pays for the file's handle
  Capability file = invoke<Capability>(
      s_invoke, rw[SLOT_FS_OPEN], home, ro_str("visits.txt"),
      init::FS_READ | init::FS_ADD, memory_quota);
  if (init::cap_error(file, 0) == init::FS_NOT_FOUND) {  // the first visit
    file = invoke<Capability>(s_invoke, rw[SLOT_FS_CREATE], home,
                              ro_str("visits.txt"), rw[SLOT_DISK], 0u,
                              memory_quota);
  }
  if (!capability_is_valid(file)) {
    out_status("[hello]    could not open visits.txt",
               init::cap_error(file, init::FS_BAD_REQUEST));
    return;
  }

  size_t length = append(s_text, 0, sizeof(s_text), "hello was here");
  if (args[0] != '\0') {
    length = append(s_text, length, sizeof(s_text), " with: ");
    length = append(s_text, length, sizeof(s_text), args);
  }
  length = append(s_text, length, sizeof(s_text), "\n");
  const int64_t written = invoke<int64_t>(
      s_invoke, rw[SLOT_FS_WRITE], file, region(s_text, length),
      init::FS_APPEND, uint64_t{length}, rw[SLOT_DISK]);
  if (written < 0) {
    out_status("[hello]    could not write visits.txt", written);
    return;
  }

  uint64_t visits = 0;
  int64_t bytes_read = 0;
  for (uint64_t offset = 0; (bytes_read = read_text(rw, file, offset)) > 0;) {
    for (int64_t i = 0; i < bytes_read; ++i) {
      visits += s_text[i] == '\n' ? 1 : 0;
    }
    offset += static_cast<uint64_t>(bytes_read);
  }
  if (bytes_read < 0) {
    out_status("[hello]    could not read visits.txt back", bytes_read);
    return;
  }
  out_dec("[hello]    visit number ", visits, " (visits.txt keeps count)\n");

  init::FsStat stat{};
  if (invoke<int64_t>(s_invoke, rw[SLOT_FS_STAT], rw[SLOT_DISK],
                      region(&stat, sizeof(stat))) == init::FS_OK) {
    out_dec("[hello]    my disk quota: ", stat.used, " of ");
    out_dec("", stat.size, " bytes used\n");
  }
}

}  // namespace

SIGNETOS_DEFAULT_FAULT_HANDLER("hello")

extern "C" int64_t compartment_main(Capability arg) {
  Capability* rw = rw_table();
  s_invoke = rw[SLOT_SYS_COMP_INVOKE];
  s_uart = rw[SLOT_UART_SENTRY];
  if (!sealing::is_sealed_as(OType::EntryPoint, s_uart)) {
    return -1;  // no console, nothing to say it with
  }

  // The request: a bounded, writable, unsealed capability from the shell.
  if (!capability_is_valid(arg) || sealing::is_sealed(arg) ||
      !capability_has_perms(arg, perms::Load | perms::Store) ||
      capability_get_length(arg) < sizeof(init::AppRequest)) {
    out("[hello]    not invoked with an AppRequest\n");
    return -1;
  }
  auto* request = reinterpret_cast<init::AppRequest*>(arg);
  request->args[init::APP_ARGS_MAX - 1] = '\0';  // a string, whatever was sent

  out("[hello]    Hello from a program loaded off the disk into a "
      "compartment of its own\n");
  if (request->args[0] != '\0') {
    out("[hello]    arguments: ");
    out(request->args);
    out("\n");
  } else {
    out("[hello]    no arguments\n");
  }

  record_visit(rw, request->args);

  // The message of the day, if we were given one to read.
  const Capability motd = rw[SLOT_MOTD];
  if (sealing::is_sealed(motd) && read_text(rw, motd, 0) >= 0) {
    out("[hello]    motd: ");
    out(s_text);
    size_t length = 0;
    while (s_text[length] != '\0') {
      ++length;
    }
    if (length == 0 || s_text[length - 1] != '\n') {
      out("\n");
    }
  }

  request->status = 0;
  return 0;
}

}  // namespace signetos::user
