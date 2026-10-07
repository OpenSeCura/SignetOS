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

#pragma once

//
// runtime.hpp - Shared User-Space Compartment Runtime Helpers
//
// Included by standalone user-space compartments in `src/user/*.cpp`.
// Provides zero-overhead inline accessors for the compartment's capability
// table (`cgp`), console output via the `uart` compartment sentry, and image
// loading with `__cap_relocs` relocation.
//
// Every helper that reaches the kernel takes the compartment's switcher
// (`invoke_gate`, the `compartment_invoke` slot) as its first argument: a
// kernel entry such as `sys_sentry` is an `OType::EntryPoint` handle that can
// only be passed to the switcher, never jumped to (`syscall::call`).
//

#include <signetos/compartment.hpp>
#include "abi.hpp"
#include "manifest.hpp"
#include <signetos/sealing.hpp>
#include <signetos/syscall.hpp>
#include <signetos/types.hpp>
#include <signetos/vm.hpp>

namespace signetos::user {

// Returns the compartment's capability table (`cgp`).
__attribute__((always_inline)) inline Capability* rw_table() {
  Capability* rw = nullptr;
  __asm__ volatile("cmv %0, cgp\n" : "=C"(rw));
  return rw;
}

// Invokes a compartment or kernel entry point `entry` through `invoke_gate`
// with up to five arguments in `ca1..ca5` (callee `ca0..ca4`) and returns
// `R` from `ca0`.
template <typename R = uint64_t, typename... A>
__attribute__((always_inline)) inline R invoke(Capability invoke_gate,
                                               Capability entry, A... args) {
  static_assert(sizeof...(A) <= 5,
                "an entry takes at most five arguments (ca1..ca5)");
  using Switcher = R (*)(Capability, A...);
  return reinterpret_cast<Switcher>(invoke_gate)(entry, args...);
}

// Bounds a NUL-terminated string `s` to its bytes (including the NUL) and
// restricts it to `perms::Load` so a callee can read it and nothing else.
inline Capability ro_str(const char* s) {
  if (s == nullptr) {
    return nullptr;
  }
  size_t len = 0;
  while (s[len] != '\0') {
    len += 1;
  }
  Capability cap = reinterpret_cast<Capability>(const_cast<char*>(s));
  cap = capability_set_bounds(cap, len + 1);
  return capability_and_perms(cap, perms::Load);
}

// Prints a null-terminated string literal by invoking `uart_sentry` via
// `invoke_gate`.
inline void print(Capability invoke_gate, Capability uart_sentry,
                  const char* msg) {
  if (!capability_is_valid(invoke_gate) || !capability_is_valid(uart_sentry) ||
      msg == nullptr) {
    return;
  }
  invoke(invoke_gate, uart_sentry, ro_str(msg));
}

// Prints `prefix`, then `value` in decimal, then `suffix`.
inline void print_dec(Capability invoke_gate, Capability uart_sentry,
                      const char* prefix, uint64_t value, const char* suffix) {
  char buf[21];
  size_t pos = sizeof(buf) - 1;
  buf[pos] = '\0';
  do {
    buf[--pos] = static_cast<char>('0' + (value % 10));
    value /= 10;
  } while (value != 0 && pos > 0);
  print(invoke_gate, uart_sentry, prefix);
  print(invoke_gate, uart_sentry, &buf[pos]);
  print(invoke_gate, uart_sentry, suffix);
}

// Prints one manifest entry the way a launcher reports it: its kind and what
// identifies it -- `syscall vm_allocate`, `service fs.open`, `disk "" rw
// 65536/8`, `file motd.txt ro`, `irq 9`, ... -- with no newline.
inline void print_manifest_entry(Capability invoke_gate, Capability uart_sentry,
                                 const init::ManifestEntry& e) {
  auto out = [&](const char* s) { print(invoke_gate, uart_sentry, s); };
  auto dec = [&](uint64_t v) { print_dec(invoke_gate, uart_sentry, "", v, ""); };
  out(init::manifest_kind_name(e.kind));
  switch (e.kind) {
    case init::MANIFEST_SYSCALL:
      out(" ");
      out(init::manifest_syscall_name(e.count));
      break;
    case init::MANIFEST_SERVICE:
    case init::MANIFEST_MMIO:
      out(" ");
      out(e.name);
      break;
    case init::MANIFEST_DISK:
      out(" \"");
      out(e.name);
      out((e.perms & perms::Store) != 0 ? "\" rw " : "\" ro ");
      if (e.amount == init::MANIFEST_ALL) {
        out("all");
      } else {
        dec(e.amount);
      }
      out("/");
      if (e.count == init::MANIFEST_ALL_INODES) {
        out("all");
      } else {
        dec(e.count);
      }
      break;
    case init::MANIFEST_FILE:
      out(" ");
      out(e.name);
      out((e.perms & perms::Store) != 0 ? " rw" : " ro");
      break;
    case init::MANIFEST_DMA:
    case init::MANIFEST_QUOTA_THREAD:
      out(" ");
      dec(e.amount);
      break;
    case init::MANIFEST_IRQ:
    case init::MANIFEST_EXC:
    case init::MANIFEST_ROOT:
    default:
      out(" ");
      dec(e.count);
      break;
  }
}

// Mints an `OType::EntryPoint` for `fn`, a function inside this compartment's
// own image: the code capability is derived from the running `pcc` (bounded
// to the image's `[0, got_end)`, `CodeRx`) re-addressed to `fn`, which `sys_sentry` accepts
// because the compartment owns that memory. `sentry_gate` is the `sentry`
// kernel entry, reached through the switcher `invoke_gate`.
inline Capability mint_entry(Capability invoke_gate, Capability sentry_gate,
                             Capability self_comp, const void* fn) {
  Capability pcc;
  __asm__ volatile("auipcc %0, 0" : "=C"(pcc));
  Capability code = capability_set_address(
      pcc, capability_get_address(
               reinterpret_cast<Capability>(const_cast<void*>(fn))));
  using FnSentry = decltype(&sys_sentry);
  return syscall::call<FnSentry>(invoke_gate, sentry_gate, self_comp, code);
}

// Naming service clients.
inline int64_t publish_name(Capability invoke_gate, Capability publish_entry,
                            const char* name, Capability sentry) {
  if (!capability_is_valid(invoke_gate) || !capability_is_valid(publish_entry) ||
      name == nullptr) {
    return init::NAMING_BAD_REQUEST;
  }
  return invoke<int64_t>(invoke_gate, publish_entry, ro_str(name), sentry);
}

inline Capability lookup_name(Capability invoke_gate, Capability lookup_entry,
                              const char* name, int64_t* out_status = nullptr) {
  if (!capability_is_valid(invoke_gate) || !capability_is_valid(lookup_entry) ||
      name == nullptr) {
    if (out_status != nullptr) {
      *out_status = init::NAMING_BAD_REQUEST;
    }
    return nullptr;
  }
  Capability res = invoke<Capability>(invoke_gate, lookup_entry, ro_str(name));
  if (capability_is_valid(res)) {
    if (out_status != nullptr) {
      *out_status = init::NAMING_OK;
    }
    return res;
  }
  if (out_status != nullptr) {
    *out_status = init::cap_error(res, init::NAMING_BAD_REQUEST);
  }
  return nullptr;
}

// Copies a standalone compartment binary image (`img_cap`) into a fresh
// allocation inside `target_comp` funded by `target_quota`, resolves its
// internal `__cap_relocs` entries into `.got`, and mints its `OType::EntryPoint`
// (`CT = 12`) entry sentry. `alloc_gate` and `sentry_gate` are the
// `vm_allocate` and `sentry` kernel entries, reached through the switcher
// `invoke_gate`.
inline Capability load_compartment_image(Capability invoke_gate,
                                         Capability alloc_gate,
                                         Capability sentry_gate,
                                         Capability target_comp,
                                         Capability target_quota,
                                         Capability img_cap) {
  if (!capability_is_valid(invoke_gate) || !capability_is_valid(alloc_gate) ||
      !capability_is_valid(sentry_gate) || !capability_is_valid(target_comp) ||
      !capability_is_valid(target_quota)) {
    return nullptr;
  }
  const init::CompartmentImageHeader* hdr = init::image_header(img_cap);
  if (hdr == nullptr) {
    return nullptr;
  }

  using FnAlloc = decltype(&sys_vm_allocate);
  using FnSentry = decltype(&sys_sentry);

  Capability code_mem = syscall::call<FnAlloc>(
      invoke_gate, alloc_gate, target_comp, target_quota,
      init::image_alloc_size(hdr, img_cap), FLAG_ZERO);
  if (!capability_is_valid(code_mem)) {
    return nullptr;
  }

  init::image_install(code_mem, img_cap, hdr);

  // Entry (and so the compartment's `pcc`) covers `[0, got_end)` only.
  Capability code = init::image_code_window(code_mem, hdr);
  if (!capability_is_valid(code)) {
    return nullptr;
  }
  return syscall::call<FnSentry>(invoke_gate, sentry_gate, target_comp, code);
}

}  // namespace signetos::user
