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
 * syscall.cpp - SignetOS system call entries and bodies
 *
 * A system call is a kernel entry: an `EntryRecord` in `s_entries` with
 * `ENTRY_FLAG_TRUSTED` set, whose `pcc` is the body below (or, for
 * `sys_thread_switch`, the assembly in kernel/switch.S). A compartment holds
 * it as an `OType::EntryPoint` handle and reaches it through the switcher
 * (`sys_compartment_invoke`, also switch.S), which runs the body on
 * `SYSCALL_STACK_BYTES` of the caller's own stack with interrupts masked and
 * hands the body's `ca0` back through the outbound capability check. Each subsystem
 * acquires its own fine-grained per-object or subsystem locks (lock.hpp).
 */

#include <signetos/compartment.hpp>
#include <signetos/quota.hpp>
#include <signetos/revoke.hpp>
#include <signetos/sealing.hpp>
#include <signetos/sentry.hpp>
#include <signetos/syscall.hpp>
#include <signetos/irq.hpp>
#include <signetos/thread.hpp>
#include <signetos/trap.hpp>
#include <signetos/vm.hpp>
#include <signetos/debug/inspect.hpp>
#include <signetos/debug/report.hpp>

namespace signetos::syscall {
namespace {

// One record per `Id`. The `compartment_invoke` slot stays empty: the switcher
// is not entered through a record, it is the thing that reads them.
alignas(16) sentry::EntryRecord s_entries[kSyscallCount];

// The switcher as a `CT = 1` sentry, derived once from the boot PCC (which
// carries AccessSystemRegs; a sentry derived later from some other PCC might
// not, and the switcher's first instruction is a CSR access).
Capability s_invoke_gate = nullptr;

// Stack each entry asks of its caller. Only `thread_switch` and `trap_wait`
// are special: the `TrapFrame` they park their caller in and the C++ they
// call live on the kernel stack.
constexpr uint64_t stack_for(Id id) {
  return id == Id::thread_switch || id == Id::trap_wait ? 0
                                                        : SYSCALL_STACK_BYTES;
}

}  // namespace

// True if the kernel may store a capability at `where`, a capability the
// caller passed for a call's second result: the caller could have stored a
// capability there itself, it is 16-byte aligned, it is in the dynamic range
// (where every thread stack and allocation is, so never a device register),
// and it is outside the slice of the caller's stack this call runs on (the
// kernel's own frame is there). Checked before the call does anything else,
// so that a bad `where` costs the caller nothing.
static bool can_store_at(Capability where) {
  if (!capability_is_valid(where) || sealing::is_sealed(where) ||
      !capability_has_perms(where, perms::Store | perms::StoreCapability)) {
    return false;
  }
  const uint64_t addr = capability_get_address(where);
  const uint64_t base = capability_get_base(where);
  const uint64_t len = capability_get_length(where);
  if (addr % sizeof(Capability) != 0 || addr < base || addr - base > len ||
      len - (addr - base) < sizeof(Capability)) {
    return false;
  }
  if (addr < vm::DYNAMIC_BASE || addr > vm::DYNAMIC_TOP - sizeof(Capability)) {
    return false;
  }
  const Capability sp = __builtin_cheri_stack_get();
  const uint64_t sp_base = capability_get_base(sp);
  const uint64_t sp_top = sp_base + capability_get_length(sp);
  if (addr < sp_top && sp_base < addr + sizeof(Capability)) {
    return false;
  }
  return true;
}

// Stores `value` at `where`, which `can_store_at` accepted, if it is in RAM
// (vm.hpp, KERNEL ACCESS). Stores nothing and returns false if it is not.
static bool store_at(Capability where, Capability value) {
  const vm::ResidentHold hold(capability_get_address(where), sizeof(Capability));
  if (!hold.ok()) {
    return false;
  }
  inspect::assert_user_capability(value, "syscall::store_at");
  *reinterpret_cast<Capability*>(where) = value;
  return true;
}

void init() {
  // The kernel's live PCC: `boot.S` bounded it to `[_kernel_start, _got_end)`
  // with `CodeRx | AccessSystemRegs` (no Store, Seal or Unseal), which is
  // exactly the capability a kernel entry must run with and the only shape
  // `inspect::assert_user_capability` accepts for an ASR sentry.
  Capability pcc;
  __asm__ volatile("auipcc %0, 0" : "=C"(pcc));
  Capability kcode =
      capability_and_perms(pcc, perms::CodeRx | perms::AccessSystemRegs);
  if (!capability_is_valid(kcode) ||
      (capability_get_perms(kcode) &
       (perms::Store | perms::Seal | perms::Unseal)) != 0) {
    debug::panic("syscall: kernel PCC is not a usable entry capability");
  }
  auto at = [&](const void* fn) -> Capability {
    return capability_set_address(
        kcode, capability_get_address(
                   reinterpret_cast<Capability>(const_cast<void*>(fn))));
  };

  s_invoke_gate = sealing::seal_entry(
      at(reinterpret_cast<const void*>(&sys_compartment_invoke)));
  if (!capability_is_valid(s_invoke_gate)) {
    debug::panic(
        "syscall: cannot seal the switcher gate: call sentries need a QEMU "
        "with toolchain/sentries applied, run with -cpu ...,sentries=on");
  }

  size_t i = 0;
#define SIGNETOS_SYSCALL_RECORD(n)                                   \
  s_entries[i] = sentry::EntryRecord{                                \
      at(reinterpret_cast<const void*>(&sys_##n)), nullptr, nullptr, \
      sentry::ENTRY_FLAG_TRUSTED, stack_for(static_cast<Id>(i))};    \
  i += 1;
  SIGNETOS_SYSCALLS(SIGNETOS_SYSCALL_RECORD)
#undef SIGNETOS_SYSCALL_RECORD
  s_entries[static_cast<size_t>(Id::compartment_invoke)] = sentry::EntryRecord{};
}

Capability gate(Id id) {
  const size_t i = static_cast<size_t>(id);
  if (i >= kSyscallCount || !capability_is_valid(s_invoke_gate)) {
    return nullptr;
  }
  if (id == Id::compartment_invoke) {
    return s_invoke_gate;
  }
  Capability record = capability_set_bounds(
      reinterpret_cast<Capability>(&s_entries[i]), sizeof(sentry::EntryRecord));
  return sentry::handle_for(record);
}

}  // namespace signetos::syscall

// A void body's `ca0` still travels back through the switcher's outbound
// capability check (`__signetos_switcher_return`). Clear it so no kernel-internal
// capability can leak out as a stale return value. Always the last statement.
#define SIGNETOS_CLEAR_RETURN() __asm__ volatile("cmv ca0, cnull" ::: "ca0")

// --- Virtual memory --------------------------------------------------------

// Marshalling only. Neither call has a status channel, so the detailed
// reason is discarded: allocate reports failure as NULL, deallocate
// reports nothing at all.

extern "C" capability_t sys_vm_allocate(capability_compartment_t comp,
                                        capability_quota_vm_t mem_quota,
                                        size_t size, uint32_t flags) {
  return ::signetos::compartment::allocate(comp, mem_quota, size, flags);
}

extern "C" void sys_vm_deallocate(capability_compartment_t comp,
                                  capability_quota_vm_t mem_quota,
                                  capability_t mem_capability) {
  ::signetos::compartment::deallocate(comp, mem_quota, mem_capability);
  SIGNETOS_CLEAR_RETURN();
}

// NOTE: Implemented for now as a synchronous up-front memory copy; we will
// return later to make this lazy page-table copy-on-write.
extern "C" capability_t sys_cow(capability_compartment_t comp,
                                capability_quota_vm_t mem_quota,
                                capability_data_t src_memory, size_t len) {
  return ::signetos::compartment::cow(comp, mem_quota, src_memory, len);
}

extern "C" uint64_t sys_revoke(capability_compartment_t comp,
                               capability_t mem_cap) {
  uint64_t epoch = 0;
  if (::signetos::revoke::revoke(comp, mem_cap, &epoch) !=
      ::signetos::revoke::Status::Ok) {
    return 0;
  }
  return epoch;
}

extern "C" uint64_t sys_revoke_query(void) {
  return ::signetos::revoke::query();
}

extern "C" uint64_t sys_revoke_start(void) {
  return ::signetos::revoke::start();
}

extern "C" uint64_t sys_revoke_step(size_t pages) {
  return ::signetos::revoke::step(pages);
}

// --- Virtual memory quotas -------------------------------------------------
// Not implemented: the roots are minted at boot by main.cpp, not by a call.
extern "C" capability_quota_vm_t sys_quota_vm_create_root(
    size_t total_system_bytes) {
  (void)total_system_bytes;
  return nullptr;
}

extern "C" capability_quota_vm_t sys_quota_vm_derive(
    capability_quota_vm_t parent_quota, size_t amount_bytes,
    uint32_t permissions) {
  return ::signetos::quota::derive(parent_quota, amount_bytes, permissions);
}

extern "C" int sys_quota_vm_destroy(capability_quota_vm_t quota) {
  return (::signetos::quota::destroy(quota) == ::signetos::quota::Status::Ok)
             ? 0
             : -1;
}

// --- Thread memory quotas --------------------------------------------------
// Not implemented: the roots are minted at boot by main.cpp, not by a call.
extern "C" capability_quota_thread_mem_t sys_quota_thread_mem_create_root(
    size_t total_bytes) {
  (void)total_bytes;
  return nullptr;
}

extern "C" capability_quota_thread_mem_t sys_quota_thread_mem_derive(
    capability_quota_thread_mem_t parent_quota, size_t amount_bytes,
    uint32_t permissions) {
  return ::signetos::thread::derive_quota(parent_quota, amount_bytes, permissions);
}

extern "C" int sys_quota_thread_mem_destroy(
    capability_quota_thread_mem_t quota) {
  return (::signetos::thread::destroy_quota(quota) ==
          ::signetos::thread::Status::Ok)
             ? 0
             : -1;
}

// --- Compartments and entry points -----------------------------------------

// This call has no status channel, so the detailed reason for a refusal is
// discarded and the caller sees NULL.
extern "C" capability_compartment_t sys_compartment_create(
    capability_quota_vm_t mem_quota, capability_data_t initial_capabilities,
    capability_data_t image, capability_data_t out_loader, uint32_t flags) {
  // Null, not merely untagged: an image whose tag was cleared (a revoked
  // buffer, say) still makes a compartment that loads itself (and finds
  // nothing to load), never one with the full handle.
  if (image == nullptr) {
    return ::signetos::compartment::create(mem_quota, initial_capabilities,
                                           flags);
  }
  if (!::signetos::syscall::can_store_at(out_loader)) {
    return nullptr;
  }
  capability_t loader = nullptr;
  const capability_compartment_t comp =
      ::signetos::compartment::create_from_image(
          mem_quota, initial_capabilities, image, flags, &loader);
  if (!::signetos::capability_is_valid(comp)) {
    return nullptr;
  }
  // The caller cannot use the compartment without its loader, so if the
  // loader cannot be handed over (`out_loader` is not in RAM) the
  // compartment is not kept either.
  if (!::signetos::syscall::store_at(out_loader, loader)) {
    ::signetos::compartment::destroy(comp);
    return nullptr;
  }
  return comp;
}

// Marshalling only. This call has no status channel either, so a
// refusal (a handle that is not genuine, one already destroyed, or one some
// thread is still inside) is silent.
extern "C" void sys_compartment_destroy(capability_compartment_t comp) {
  ::signetos::compartment::destroy(comp);
  SIGNETOS_CLEAR_RETURN();
}

extern "C" Sentry sys_sentry(capability_compartment_t comp,
                             capability_exec_t code) {
  return ::signetos::sentry::create(comp, code, ::signetos::perms::CodeRx);
}

extern "C" uint64_t sys_fault_install(capability_compartment_t comp,
                                      capability_exec_t code) {
  return static_cast<uint64_t>(
      ::signetos::compartment::install_fault_handler(comp, code));
}

// --- Threads ---------------------------------------------------------------

extern "C" capability_thread_t sys_thread_create(
    capability_quota_thread_mem_t thread_mem_quota, size_t stack_size,
    Sentry entry_point, capability_t initial_arg) {
  return ::signetos::thread::create(thread_mem_quota, stack_size, entry_point, initial_arg);
}

extern "C" void sys_thread_exit(int status) {
  ::signetos::thread::exit(status);
  SIGNETOS_CLEAR_RETURN();
}

extern "C" uint64_t sys_thread_kill(capability_thread_t thread) {
  return static_cast<uint64_t>(::signetos::thread::kill(thread));
}

extern "C" uint64_t sys_thread_tid(capability_thread_t thread) {
  return ::signetos::thread::tid_of(thread);
}

// --- Traps and interrupts --------------------------------------------------

extern "C" uint64_t sys_trap_install(capability_thread_t thread) {
  return static_cast<uint64_t>(::signetos::irq::install(thread));
}

// --- Paging ------------------------------------------------------------------
#if defined(SIGNETOS_PAGING)

extern "C" uint64_t sys_page_setup(size_t slots) {
  return static_cast<uint64_t>(::signetos::vm::setup_paging(slots));
}

extern "C" uint64_t sys_page_next(capability_data_t buf) {
  return ::signetos::vm::page_next(buf, ::signetos::thread::current_tid());
}

extern "C" void sys_page_done(capability_data_t buf) {
  ::signetos::vm::page_done(buf);
  SIGNETOS_CLEAR_RETURN();
}

extern "C" uint64_t sys_page_test(uint64_t op, capability_t cap) {
  return ::signetos::vm::page_test(op, cap);
}

#endif  // SIGNETOS_PAGING
