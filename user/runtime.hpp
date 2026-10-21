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
// Included by standalone user-space compartments in `boot/` and `external/`.
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
#include <signetos/fault.hpp>
#include <signetos/hw/platform.hpp>
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
// 65536/8`, `file motd.txt ro`, `irq 11`, ... -- with no newline.
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
    case init::MANIFEST_QUOTA_VM:
      break;
    case init::MANIFEST_QUOTA_SCHED:
      out(" ");
      dec(e.amount);
      out("/");
      dec(e.count);
      out(" us class ");
      dec(e.param);
      break;
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

// The number of the hart this is running on, from `utidc` (platform.hpp).
inline uint64_t this_hart() {
  Capability id;
  __asm__ volatile("csrr %0, 0x480" : "=C"(id));  // 0x480 = utidc
  return capability_get_address(id) & platform::UTIDC_HART_MASK;
}

// The kernel's id for the thread this is running on, from `utidc`: the same
// number `sys_thread_tid` and the scheduler use.
inline uint64_t self_tid() {
  Capability id;
  __asm__ volatile("csrr %0, 0x480" : "=C"(id));  // 0x480 = utidc
  return capability_get_address(id) >> platform::UTIDC_TID_SHIFT;
}

// Locks. A lock is a `uint64_t` in the memory of the compartment whose state
// it protects, 0 when free (abi.hpp, scheduler). `lock_wait` and `lock_wake`
// are the scheduler's `sched.lock_wait` and `sched.lock_wake`.

// `word` as the scheduler takes it: its eight bytes, Load|Store.
inline Capability lock_word_cap(uint64_t* word) {
  Capability cap = capability_set_bounds(reinterpret_cast<Capability>(word),
                                         sizeof(uint64_t));
  return capability_and_perms(cap, perms::Load | perms::Store);
}

// Takes the lock at `word`, sleeping in the scheduler while another thread
// holds it. SCHED_OK once it is held. SCHED_OWNER_DEAD once it is held, but
// the previous owner ended without releasing it, so what it protects may be
// half-updated. Anything else means it was not taken: SCHED_DEADLOCK if the
// caller holds it already, or the owner is waiting for the caller.
inline int64_t lock(Capability invoke_gate, Capability lock_wait,
                    uint64_t* word) {
  const uint64_t me = self_tid();
  for (;;) {
    uint64_t seen = 0;
    if (__atomic_compare_exchange_n(word, &seen, me, false, __ATOMIC_SEQ_CST,
                                    __ATOMIC_SEQ_CST)) {
      return init::SCHED_OK;
    }
    if ((seen & ~init::LOCK_WAITERS) == me) {
      return init::SCHED_DEADLOCK;
    }
    if (!capability_is_valid(lock_wait)) {
      return init::SCHED_BAD_REQUEST;  // nowhere to wait: leave the word alone
    }
    // The flag tells the owner to call `lock_wake` when it releases the lock.
    if ((seen & init::LOCK_WAITERS) == 0) {
      const uint64_t flagged = seen | init::LOCK_WAITERS;
      if (!__atomic_compare_exchange_n(word, &seen, flagged, false,
                                       __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        continue;  // it changed meanwhile: look again
      }
      seen = flagged;
    }
    const int64_t st =
        invoke<int64_t>(invoke_gate, lock_wait, lock_word_cap(word), seen);
    if ((__atomic_load_n(word, __ATOMIC_SEQ_CST) & ~init::LOCK_WAITERS) == me) {
      return st == init::SCHED_OWNER_DEAD ? st : init::SCHED_OK;
    }
    if (st != init::SCHED_OK) {
      return st;
    }
  }
}

// Releases the lock at `word`, which the caller holds. If anyone is waiting
// for it, the scheduler hands it to the next of them.
inline void unlock(Capability invoke_gate, Capability lock_wake,
                   uint64_t* word) {
  uint64_t expected = self_tid();
  if (!__atomic_compare_exchange_n(word, &expected, 0, false, __ATOMIC_SEQ_CST,
                                   __ATOMIC_SEQ_CST)) {
    invoke<int64_t>(invoke_gate, lock_wake, lock_word_cap(word));
  }
}

// How often `revoke_wait` looks.
constexpr uint64_t REVOKE_POLL_US = 100'000;

// Waits until the completed epoch reaches `epoch`, looking
// (`sys_revoke_query`, which sweeps when it may) every REVOKE_POLL_US and
// sleeping in the scheduler (`sched_block`) in between.
inline void revoke_wait(Capability invoke_gate, Capability query_gate,
                        Capability sched_block, uint64_t epoch) {
  while (syscall::call<decltype(&sys_revoke_query)>(invoke_gate, query_gate) <
         epoch) {
    invoke<int64_t>(invoke_gate, sched_block, REVOKE_POLL_US);
  }
}

// Copies a standalone compartment binary image (`img_cap`) into a fresh
// allocation inside `target_comp` funded by `target_quota`, resolves its
// internal `__cap_relocs` entries into `.got`, and mints its `OType::EntryPoint`
// (`CT = 18`) entry sentry. `alloc_gate`, `sentry_gate` and `fault_gate` are
// the `vm_allocate`, `sentry` and `fault_install` kernel entries, reached
// through the switcher `invoke_gate`.
inline Capability load_compartment_image(Capability invoke_gate,
                                         Capability alloc_gate,
                                         Capability sentry_gate,
                                         Capability fault_gate,
                                         Capability target_comp,
                                         Capability target_quota,
                                         Capability img_cap) {
  if (!capability_is_valid(invoke_gate) || !capability_is_valid(alloc_gate) ||
      !capability_is_valid(sentry_gate) || !capability_is_valid(fault_gate) ||
      !capability_is_valid(target_comp) || !capability_is_valid(target_quota)) {
    return nullptr;
  }
  const init::CompartmentImageHeader* hdr = init::image_header(img_cap);
  if (hdr == nullptr) {
    return nullptr;
  }

  using FnAlloc = decltype(&sys_vm_allocate);
  using FnSentry = decltype(&sys_sentry);
  using FnFaultInstall = decltype(&sys_fault_install);

  Capability code_mem = syscall::call<FnAlloc>(
      invoke_gate, alloc_gate, target_comp, target_quota,
      init::image_alloc_size(hdr, img_cap), 0);
  if (!capability_is_valid(code_mem)) {
    return nullptr;
  }

  init::image_install(code_mem, img_cap, hdr);

  // Entry (and so the compartment's `pcc`) covers `[0, got_end)` only.
  Capability code = init::image_code_window(code_mem, hdr);
  if (!capability_is_valid(code)) {
    return nullptr;
  }
  Capability entry =
      syscall::call<FnSentry>(invoke_gate, sentry_gate, target_comp, code);
  if (!capability_is_valid(entry)) {
    return nullptr;
  }

  // The image's fault handler (fault.hpp), if it defines one: kept in the
  // compartment's descriptor, never handed back. Any failure fails the load
  // -- a compartment that asked for a handler must not run without it -- and
  // the caller destroys the compartment.
  Capability handler_code = nullptr;
  if (!init::image_fault_handler(code, hdr->fault_handler, &handler_code)) {
    return nullptr;
  }
  if (handler_code != nullptr &&
      syscall::call<FnFaultInstall>(invoke_gate, fault_gate, target_comp,
                                    handler_code) !=
          static_cast<uint64_t>(Status::Ok)) {
    return nullptr;
  }
  return entry;
}

// Creates a compartment funded by `vm_quota` with `seeds` (matching `img_cap`'s
// manifest count), loads `img_cap` into it, and mints its entry sentry. Rolls
// back via `destroy_gate` if loading fails.
inline bool create_compartment(Capability invoke_gate, Capability create_gate,
                               Capability destroy_gate, Capability alloc_gate,
                               Capability sentry_gate, Capability fault_gate,
                               Capability vm_quota, Capability seeds,
                               Capability img_cap, Capability* out_comp,
                               Capability* out_entry) {
  *out_comp = nullptr;
  *out_entry = nullptr;
  const init::CompartmentImageHeader* hdr = init::image_header(img_cap);
  init::Manifest manifest;
  if (hdr == nullptr || !init::manifest_of(img_cap, hdr, &manifest)) {
    return false;
  }
  const size_t seeds_len =
      capability_is_valid(seeds) ? capability_get_length(seeds) : 0;
  if (seeds_len != static_cast<size_t>(manifest.count) * sizeof(Capability)) {
    return false;
  }

  using FnCompCreate = decltype(&sys_compartment_create);
  const Capability comp =
      syscall::call<FnCompCreate>(invoke_gate, create_gate, vm_quota, seeds);
  if (!capability_is_valid(comp)) {
    return false;
  }

  Capability entry =
      load_compartment_image(invoke_gate, alloc_gate, sentry_gate, fault_gate,
                             comp, vm_quota, img_cap);
  if (!capability_is_valid(entry)) {
    using FnCompDestroy = decltype(&sys_compartment_destroy);
    syscall::call<FnCompDestroy>(invoke_gate, destroy_gate, comp);
    return false;
  }
  *out_comp = comp;
  *out_entry = entry;
  return true;
}

// --- Fault handlers (signetos/fault.hpp) -------------------------------------
//
// An image may define `compartment_error_handler(fault::ErrorState*)`
// (user/entry.S); without one, the kernel unwinds the compartment's faults.
// `SIGNETOS_DEFAULT_FAULT_HANDLER` below defines the usual one: print one
// line describing the fault, then unwind.

// One line of console text, built in a fixed buffer so it can be printed
// with a single call. Text that does not fit is dropped; `buf` is always
// NUL-terminated.
struct LineBuffer {
  char buf[160];
  size_t len = 0;

  LineBuffer() { buf[0] = '\0'; }

  // Every write goes through here: one character, if there is room for it
  // and the NUL after it.
  void put(char c) {
    if (len + 1 < sizeof(buf)) {
      buf[len] = c;
      len += 1;
      buf[len] = '\0';
    }
  }
  void str(const char* s) {
    for (; s != nullptr && *s != '\0'; ++s) {
      put(*s);
    }
  }
  void dec(uint64_t v) { num(v, 10); }
  void hex(uint64_t v) {
    str("0x");
    num(v, 16);
  }

 private:
  void num(uint64_t v, uint64_t base) {
    char digits[20];  // UINT64_MAX has 20 decimal digits
    size_t n = 0;
    do {
      const uint64_t d = v % base;
      digits[n] = static_cast<char>(d < 10 ? '0' + d : 'a' + (d - 10));
      n += 1;
      v /= base;
    } while (v != 0);
    while (n > 0) {
      n -= 1;
      put(digits[n]);
    }
  }
};

// The running code capability (PCC), which covers this image's code. A fault
// handler runs in the same code as the code that faulted, so this is how it
// reads that code (`instruction_length`) or locates a pc in it.
__attribute__((always_inline)) inline Capability own_code() {
  Capability pcc;
  __asm__ volatile("auipcc %0, 0" : "=C"(pcc));
  return pcc;
}

// The length in bytes (2 or 4) of the instruction at `pc` in this image's
// code: what a handler adds to `ErrorState::pc` to skip the faulting
// instruction. 0 if `pc` is not in this image's code (a fault on fetching
// from a bad target), where there is no instruction to skip.
inline uint64_t instruction_length(uint64_t pc) {
  const Capability code = own_code();
  const uint64_t base = capability_get_base(code);
  if (pc < base || pc - base + 2 > capability_get_length(code) ||
      !capability_has_perms(code, perms::Load)) {
    return 0;
  }
  const uint16_t low = *reinterpret_cast<const volatile uint16_t*>(
      capability_set_address(code, pc));
  return (low & 0b11) == 0b11 ? 4 : 2;
}

// The line the default fault handler prints, for the fault `state` in the
// compartment `who`:
//
//   [fs] fault in thread 5: CHERI bounds violation on data access at pc
//   0x80443a1c (image +0x1a1c), mtval 0x80450040; unwinding
//
// The image offset is the pc less the base of the running PCC, which covers
// the image's code, linked at 0: it is the address to look up in the image's
// ELF file (`llvm-addr2line -e fs.elf 0x1a1c`). It is left out when the pc
// is outside that code, as after a jump to a bad target.
inline void describe_fault(LineBuffer& out, const char* who,
                           const fault::ErrorState& state) {
  const fault::Decoded d = fault::decode(state.mcause, state.mtval2);
  out.str("[");
  out.str(who);
  out.str("] fault in thread ");
  out.dec(self_tid());
  out.str(": ");
  if (d.cls == fault::CLASS_CAPABILITY) {
    out.str("CHERI ");
    out.str(fault::violation_name(fault::detail_violation(d.detail)));
    out.str(" violation on ");
    out.str(fault::access_name(fault::detail_access(d.detail)));
  } else {
    out.str(fault::class_name(d.cls));
  }
  out.str(" at pc ");
  out.hex(state.pc);
  const Capability code = own_code();
  const uint64_t code_base = capability_get_base(code);
  if (state.pc >= code_base &&
      state.pc - code_base < capability_get_length(code)) {
    out.str(" (image +");
    out.hex(state.pc - code_base);
    out.str(")");
  }
  out.str(", mtval ");
  out.hex(state.mtval);
  out.str("; unwinding\n");
}

// The default fault handler: prints `describe_fault`'s line through the
// compartment's own `uart` sentry and unwinds.
inline uint64_t report_fault_and_unwind(const char* who,
                                        const fault::ErrorState& state,
                                        Capability invoke_gate,
                                        Capability uart_sentry) {
  LineBuffer line;
  describe_fault(line, who, state);
  print(invoke_gate, uart_sentry, line.buf);
  return fault::UNWIND;
}

}  // namespace signetos::user

// Declares a fault handler: `extern "C"`, so user/entry.S finds it by name,
// and 4-byte aligned, which the loader insists on (`init::image_fault_handler`)
// but the compiler does not otherwise promise once compressed instructions
// are on.
#define SIGNETOS_FAULT_HANDLER extern "C" __attribute__((aligned(4))) uint64_t

// Defines this image's fault handler as the default
// (`report_fault_and_unwind`); `who` names the compartment in the report.
// The handler is this compartment's own code. To print the report it calls
// the console like any other `print`, through the switcher and the `uart`
// entry in the compartment's capability table (`cgp`, which the kernel sets
// for the handler), at the slots its manifest names `SLOT_SYS_COMP_INVOKE`
// and `SLOT_UART_SENTRY`. Use it at namespace scope outside any unnamed
// namespace: the handler must have external linkage for user/entry.S to find
// it.
#define SIGNETOS_DEFAULT_FAULT_HANDLER(who)                       \
  SIGNETOS_FAULT_HANDLER compartment_error_handler(               \
      ::signetos::fault::ErrorState* state) {                     \
    const ::signetos::Capability* t = ::signetos::user::rw_table(); \
    return ::signetos::user::report_fault_and_unwind(             \
        who, *state, t[SLOT_SYS_COMP_INVOKE], t[SLOT_UART_SENTRY]); \
  }
