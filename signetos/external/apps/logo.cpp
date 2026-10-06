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
 * logo.cpp - Plays the SignetOS signet-ring wax-stamping animation
 *
 * Installed on `disk.img` as the public program `logo.bin`. Run from the
 * shell prompt with:
 *   run logo.bin [loops]
 */

#include <signetos/logo.hpp>

#include "runtime.hpp"

namespace signetos::user {
namespace {

// What it asks the shell for (user/manifest.hpp): the switcher and the
// console, and nothing else -- an animation needs no disk.
#define LOGO_MANIFEST(X)                                 \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)      \
  M_SERVICE(X, UART_SENTRY, "uart")
SIGNETOS_MANIFEST(LOGO_MANIFEST, 64 * 1024)

}  // namespace

extern "C" void compartment_main(Capability arg) {
  Capability* rw = rw_table();
  Capability invoke = rw[SLOT_SYS_COMP_INVOKE];
  Capability uart = rw[SLOT_UART_SENTRY];
  if (!sealing::is_sealed_as(OType::EntryPoint, uart)) {
    return;
  }

  if (!capability_is_valid(arg) || sealing::is_sealed(arg) ||
      !capability_has_perms(arg, perms::Load | perms::Store) ||
      capability_get_length(arg) < sizeof(init::AppRequest)) {
    print(invoke, uart, "[logo]     not invoked with an AppRequest\n");
    return;
  }
  auto* req = reinterpret_cast<init::AppRequest*>(arg);
  req->args[init::APP_ARGS_MAX - 1] = '\0';

  // Optional repeat count in `req->args` (default 1, max 10).
  uint64_t loops = 0;
  const char* p = req->args;
  while (*p == ' ') {
    ++p;
  }
  while (*p >= '0' && *p <= '9') {
    loops = loops * 10 + static_cast<uint64_t>(*p - '0');
    if (loops > 10) {
      loops = 10;
    }
    ++p;
  }
  if (loops == 0) {
    loops = 1;
  }

  const uint64_t ticks_per_us = (req->ticks_per_us > 0) ? req->ticks_per_us : 10;
  const uint64_t ticks_per_ms = ticks_per_us * 1000ULL;

  auto out = [&](const char* s) { print(invoke, uart, s); };

  for (uint64_t i = 0; i < loops; ++i) {
    if (i > 0) {
      // Hold the completed seal for 400 ms, then rewind 9 lines so the next
      // pass animates in place in the same box.
      const uint64_t wait_ticks = ticks_per_ms * 400ULL;
      uint64_t start = 0;
      __asm__ volatile("rdtime %0" : "=r"(start));
      uint64_t now = start;
      while (now - start < wait_ticks) {
        __asm__ volatile("rdtime %0" : "=r"(now));
      }
      out("\x1b[9A\r");
    }
    logo::play(out, ticks_per_ms, true);
  }

  req->status = 0;
}

}  // namespace signetos::user
