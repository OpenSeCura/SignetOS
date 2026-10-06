/*
 * Copyright 2026 Google LLC (Cherified Team)
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
 * Not part of the system. `apps/hello.bin` is written to `/bin` on the disk
 * image (`tools/signetfs.py put --dir bin`, see the Makefile); the shell
 * holds a read-only disk quota rooted there, and its `run hello.bin [args]`
 * reads the file through it, has `loader` make a compartment of it, invokes
 * `compartment_main` once with an `AppRequest` (abi.hpp, "Applications") and
 * destroys the compartment when it returns.
 *
 * WHAT IT HOLDS
 *   Exactly what its manifest (below; user/manifest.hpp) asked for and the
 *   shell's policy granted: the switcher, the console, a `quota_disk` node of
 *   its own -- a directory the shell makes for it under `/home`, 64 KiB and 8
 *   inodes of the shell's own allowance, removed again with everything in it
 *   when the program returns -- the file-system entry points to use it with,
 *   and, if the shell has one to give, a read-only handle on `/home/motd.txt`.
 *   It writes a note into its directory, reads it back, says how much of its
 *   allowance that took, and prints the message of the day if there is one.
 *
 *   The directory is the whole of the disk as far as this program is
 *   concerned: the handle is rooted there, so `/home` itself, the shell's
 *   files, `/bin`, are not in view, let alone writable. And there is nothing
 *   to ask for more with: a program is a compartment like any other, with
 *   nothing it was not given.
 */

#include "runtime.hpp"

namespace signetos::user {
namespace {

// --- What `hello` asks the shell for (user/manifest.hpp) ----------------------
// HOME is required: this program is about having a directory, so without one
// it is not started. The message of the day is not: a null slot means the
// shell had no `motd.txt` to give, or chose not to, and either is fine.
#define HELLO_MANIFEST(X)                                                   \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)                         \
  M_SERVICE(X, UART_SENTRY, "uart")                                         \
  M_DISK(X, HOME, ::signetos::init::MANIFEST_REQUIRED,                      \
         perms::Load | perms::Store, 64 * 1024, 8, "")                      \
  M_SERVICE(X, FS_CREATE, "fs.create")                                      \
  M_SERVICE(X, FS_WRITE, "fs.write")                                        \
  M_SERVICE(X, FS_READ, "fs.read")                                          \
  M_SERVICE(X, FS_CLOSE, "fs.close")                                        \
  M_SERVICE(X, FS_QUERY, "fs.quota_query")                                  \
  M_FILE(X, MOTD, 0, perms::Load, "motd.txt")
SIGNETOS_MANIFEST(HELLO_MANIFEST, 64 * 1024)

Capability s_invoke = nullptr;
Capability s_uart = nullptr;

char s_text[128];  // what goes into the note, and what comes back out

void out(const char* msg) { print(s_invoke, s_uart, msg); }
void out_dec(const char* p, uint64_t v, const char* s) {
  print_dec(s_invoke, s_uart, p, v, s);
}
void out_status(const char* what, int64_t status) {
  out(what);
  out_dec(": status -", static_cast<uint64_t>(-status), "\n");
}

// No libc: a request struct is cleared by hand, and a string copied by hand.
void zero_bytes(void* p, size_t n) {
  auto* d = static_cast<uint8_t*>(p);
  for (size_t i = 0; i < n; ++i) {
    d[i] = 0;
  }
}
size_t append(char* dst, size_t pos, size_t cap, const char* src) {
  while (pos + 1 < cap && *src != '\0') {
    dst[pos++] = *src++;
  }
  dst[pos] = '\0';
  return pos;
}

// Invokes a file-system entry point with a request block of ours.
template <typename T>
void call(Capability entry, T* req) {
  using FnInvoke = decltype(&sys_compartment_invoke);
  Capability cap =
      capability_set_bounds(reinterpret_cast<Capability>(req), sizeof(T));
  reinterpret_cast<FnInvoke>(s_invoke)(entry, cap);
}

// Reads up to `cap - 1` bytes of `file` into `buf` and NUL-terminates them;
// the fs status.
int64_t read_into(Capability fs_read, Capability file, char* buf, size_t cap) {
  init::FsIoRequest io;
  zero_bytes(&io, sizeof(io));
  io.file = file;
  io.buf = capability_set_bounds(reinterpret_cast<Capability>(buf), cap - 1);
  io.length = cap - 1;
  io.status = init::FS_BAD_REQUEST;
  call(fs_read, &io);
  buf[io.status == init::FS_OK ? io.out_count : 0] = '\0';
  return io.status;
}

// The exercise: a file of our own, in a directory of our own.
void leave_a_note(Capability* rw, const char* args) {
  Capability home = rw[SLOT_HOME];
  if (!sealing::is_sealed(home)) {
    out("[hello]    no directory of my own\n");  // not what REQUIRED means
    return;
  }

  init::FsOpenRequest open;
  zero_bytes(&open, sizeof(open));
  open.quota = home;
  append(open.path, 0, sizeof(open.path), "note.txt");
  open.perms = perms::Load | perms::Store;
  open.status = init::FS_BAD_REQUEST;
  call(rw[SLOT_FS_CREATE], &open);
  if (open.status != init::FS_OK) {
    out_status("[hello]    could not create note.txt", open.status);
    return;
  }
  Capability file = open.out_file;

  size_t len = append(s_text, 0, sizeof(s_text), "hello was here");
  if (args[0] != '\0') {
    len = append(s_text, len, sizeof(s_text), " with: ");
    len = append(s_text, len, sizeof(s_text), args);
  }
  len = append(s_text, len, sizeof(s_text), "\n");

  init::FsIoRequest io;
  zero_bytes(&io, sizeof(io));
  io.file = file;
  io.buf = capability_set_bounds(reinterpret_cast<Capability>(s_text), len);
  io.length = len;
  io.status = init::FS_BAD_REQUEST;
  call(rw[SLOT_FS_WRITE], &io);
  if (io.status != init::FS_OK) {
    out_status("[hello]    could not write note.txt", io.status);
  } else {
    const int64_t st = read_into(rw[SLOT_FS_READ], file, s_text, sizeof(s_text));
    if (st != init::FS_OK) {
      out_status("[hello]    could not read note.txt back", st);
    } else {
      out("[hello]    note.txt reads: ");
      out(s_text);
    }
  }

  init::FsCloseRequest close;
  zero_bytes(&close, sizeof(close));
  close.file = file;
  close.status = init::FS_BAD_REQUEST;
  call(rw[SLOT_FS_CLOSE], &close);

  init::FsQueryRequest q;
  zero_bytes(&q, sizeof(q));
  q.quota = home;
  q.status = init::FS_BAD_REQUEST;
  call(rw[SLOT_FS_QUERY], &q);
  if (q.status == init::FS_OK) {
    out_dec("[hello]    my directory: ", q.used_bytes, " of ");
    out_dec("", q.limit_bytes, " bytes, ");
    out_dec("", q.used_inodes, " of ");
    out_dec("", q.limit_inodes, " inodes used\n");
  }
}

}  // namespace

extern "C" void compartment_main(Capability arg) {
  Capability* rw = rw_table();
  s_invoke = rw[SLOT_SYS_COMP_INVOKE];
  s_uart = rw[SLOT_UART_SENTRY];
  if (!sealing::is_sealed_as(OType::EntryPoint, s_uart)) {
    return;  // no console, nothing to say it with
  }

  // The request: a bounded, writable, unsealed capability from the shell.
  if (!capability_is_valid(arg) || sealing::is_sealed(arg) ||
      !capability_has_perms(arg, perms::Load | perms::Store) ||
      capability_get_length(arg) < sizeof(init::AppRequest)) {
    out("[hello]    not invoked with an AppRequest\n");
    return;
  }
  auto* req = reinterpret_cast<init::AppRequest*>(arg);
  req->args[init::APP_ARGS_MAX - 1] = '\0';  // a string, whatever was sent

  out("[hello]    Hello from a program loaded off the disk into a "
      "compartment of its own\n");
  if (req->args[0] != '\0') {
    out("[hello]    arguments: ");
    out(req->args);
    out("\n");
  } else {
    out("[hello]    no arguments\n");
  }

  leave_a_note(rw, req->args);

  // The message of the day, if the shell gave us one to read. The handle is
  // the shell's to close, not ours.
  Capability motd = rw[SLOT_MOTD];
  if (sealing::is_sealed(motd)) {
    if (read_into(rw[SLOT_FS_READ], motd, s_text, sizeof(s_text)) == init::FS_OK) {
      out("[hello]    motd: ");
      out(s_text);
      size_t n = 0;
      while (s_text[n] != '\0') {
        ++n;
      }
      if (n == 0 || s_text[n - 1] != '\n') {
        out("\n");
      }
    }
  }

  req->status = 0;
}

}  // namespace signetos::user
