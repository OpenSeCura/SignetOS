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
#include <signetos/inspect.hpp>
#include <signetos/quota.hpp>
#include <signetos/revoke.hpp>
#include <signetos/sealing.hpp>
#include <signetos/sentry.hpp>
#include <signetos/syscall.hpp>
#include <signetos/thread.hpp>
#include <signetos/trap.hpp>
#include <signetos/uart.hpp>

namespace signetos::syscall {
namespace {

// One record per `Id`. The `compartment_invoke` slot stays empty: the switcher
// is not entered through a record, it is the thing that reads them.
alignas(16) sentry::EntryRecord s_entries[kSyscallCount];

// The switcher as a `CT = 1` sentry, derived once from the boot PCC (which
// carries AccessSystemRegs; a sentry derived later from some other PCC might
// not, and the switcher's first instruction is a CSR access).
Capability s_invoke_gate = nullptr;

// Stack each entry asks of its caller. Only `thread_switch` is special: its
// `SwitchFrame` and `__signetos_thread_dispatch` live on the kernel stack.
constexpr uint64_t stack_for(Id id) {
  return id == Id::thread_switch ? 0 : SYSCALL_STACK_BYTES;
}

}  // namespace

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
    uart::panic("syscall: kernel PCC is not a usable entry capability");
  }
  auto at = [&](const void* fn) -> Capability {
    return capability_set_address(
        kcode, capability_get_address(
                   reinterpret_cast<Capability>(const_cast<void*>(fn))));
  };

  s_invoke_gate = sealing::seal_entry(
      at(reinterpret_cast<const void*>(&sys_compartment_invoke)));

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

// TODO mostly for testing, I don't want this here long term
extern "C" uint64_t sys_vm_phys(capability_compartment_t comp,
                                capability_t mem_capability) {
  return ::signetos::compartment::phys(comp, mem_capability);
}

extern "C" capability_revoker_t sys_revoke_create(
    capability_compartment_t comp, capability_t mem_cap) {
  return ::signetos::revoke::create(comp, mem_cap);
}

extern "C" capability_revoker_t sys_revoke_derive(
    capability_revoker_t parent_revoker, capability_t sub_cap,
    uint32_t permissions) {
  return ::signetos::revoke::derive(parent_revoker, sub_cap, permissions);
}

extern "C" uint64_t sys_revoke_register(capability_revoker_t revoker_cap,
                                        capability_t mem_cap,
                                        capability_quota_vm_t mem_quota) {
  uint64_t epoch = 0;
  if (::signetos::revoke::register_range(revoker_cap, mem_cap, mem_quota,
                                         &epoch) !=
      ::signetos::revoke::Status::Ok) {
    return 0;
  }
  return epoch;
}

extern "C" uint64_t sys_revoke_query(void) {
  return ::signetos::revoke::completed_epoch();
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

// --- Compartments, entry points and types ----------------------------------

// Marshalling only. This call has no status channel, so the detailed
// reason is discarded and the caller sees NULL.
extern "C" capability_compartment_t sys_compartment_create(
    capability_quota_vm_t mem_quota, capability_data_t initial_capabilities) {
  return ::signetos::compartment::create(mem_quota, initial_capabilities);
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
  ::signetos::sentry::Status s_status = ::signetos::sentry::Status::Ok;
  return ::signetos::sentry::create(comp, code, ::signetos::perms::CodeRx, &s_status);
}

extern "C" capability_type_t sys_type_mint(capability_t record) {
  return ::signetos::sealing::type_mint(record);
}

extern "C" capability_type_t sys_type_derive(capability_type_t key,
                                             uint32_t permissions) {
  return ::signetos::sealing::type_derive(key, permissions);
}

extern "C" capability_sealed_t sys_seal(capability_type_t key,
                                        capability_data_t obj) {
  capability_sealed_t out = ::signetos::sealing::user_seal(key, obj);
  if (::signetos::capability_is_valid(out)) {
    ::signetos::Capability hdr_key =
        *reinterpret_cast<const ::signetos::Capability*>(obj);
    ::signetos::inspect::assert_user_capability(hdr_key,
                                                "sys_seal:header_key");
  }
  return out;
}

extern "C" capability_data_t sys_unseal(capability_type_t key,
                                        capability_sealed_t handle) {
  return ::signetos::sealing::user_unseal(key, handle);
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

extern "C" void sys_thread_kill(capability_thread_t thread) {
  ::signetos::thread::kill(thread);
  SIGNETOS_CLEAR_RETURN();
}

extern "C" uint64_t sys_thread_tid(capability_thread_t thread) {
  return ::signetos::thread::tid_of(thread);
}

// --- Traps and interrupts --------------------------------------------------

extern "C" void sys_trap_bind(capability_compartment_t comp,
                              capability_t auth_cap,
                              Sentry target) {
  ::signetos::trap::bind(comp, auth_cap, target);
  SIGNETOS_CLEAR_RETURN();
}

extern "C" void sys_trap_unbind(capability_compartment_t comp,
                                capability_t auth_cap) {
  ::signetos::trap::unbind(comp, auth_cap);
  SIGNETOS_CLEAR_RETURN();
}
