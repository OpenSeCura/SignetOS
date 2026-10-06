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
 * trap_mgr.cpp - SignetOS User-Space Hardware Trap & Interrupt Manager
 *
 * design_spec.md sections 3.1.3 and 3.6: the service that routes hardware
 * exceptions and interrupts. The kernel delivers a vector to whoever holds
 * that vector's `OType::Trap` authority and bound it (trap.hpp); this is the
 * compartment where delivery of the *external* interrupt turns into "which
 * device, and who wants to know".
 *
 * THE PLIC
 *   Every device interrupt on the board is a PLIC source, and the PLIC
 *   presents all of them to the hart as one interrupt, `IRQ_S_EXT` (scause
 *   code 9). The kernel does not touch the PLIC: `init` delegates its register
 *   window (BootManifest, platform.hpp) to this compartment alone, together
 *   with the code 9 authority. So the PLIC is a driver like any other -- in
 *   user space, behind a capability -- and the kernel's whole part in an
 *   external interrupt is one `sie` bit and the ordinary trap delivery.
 *
 * WHICH HART
 *   The PLIC interrupts a hart only for sources enabled in that hart's
 *   context, and each source is enabled for exactly one hart: the one this
 *   compartment was set up on, which is the hart the system booted on. That
 *   is the hart that runs SignetOS, and it need not be hart 0: OpenSBI picks
 *   it, and QEMU with `-smp 4` boots on hart 1. A hart's number is in its
 *   `utidc`, where the kernel puts it (thread.cpp, `init_hart`). The claim is
 *   made in the same context, so it is always the right one for the hart
 *   taking the interrupt.
 *
 * ROUTING
 *   `trap_mgr.irq_route(source, handler)` appends `handler`, an
 *   `OType::EntryPoint`, to the source's handler list and enables the source
 *   at the PLIC the first time. The code 9 handler claims sources until the
 *   PLIC has none pending and, for each, invokes its handlers in order with a
 *   Load-only `IrqEvent`, then completes the claim -- which is what lets a
 *   level-triggered source fire again. A claimed source nobody routed is
 *   disabled on the spot rather than left to storm.
 *
 *   Routed handlers run in interrupt context: on the interrupted thread's
 *   narrowed stack, interrupts masked, in a chain of compartment switches
 *   that began in the kernel's trap path. They may invoke other compartments
 *   (the console driver invokes its reader's wake, which invokes the
 *   scheduler) but must be short and must never block or switch threads.
 *
 * `irq_route` goes back to `init` through `TrapMgrInterface` and is not
 * published by name: which device reaches which driver is a platform decision
 * `init` makes, not something any compartment holding `lookup` may.
 */

#include <signetos/platform.hpp>

#include "runtime.hpp"

namespace signetos::user {
namespace {

// --- What `trap_mgr` asks `init` for (user/manifest.hpp) ----------------------
// The external-interrupt line and the PLIC window are what routing is made
// of; the four exception bindings are the fault reporter; `vm_allocate` funds
// the per-source route pages.
#define TRAP_MGR_MANIFEST(X)                             \
  M_SYSCALL(X, SYS_TRAP_BIND, trap_bind)                 \
  M_SYSCALL(X, SYS_TRAP_UNBIND, trap_unbind)             \
  M_SYSCALL(X, SYS_VM_ALLOC, vm_allocate)                \
  M_SYSCALL(X, SYS_VM_DEALLOC, vm_deallocate)            \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)      \
  M_SYSCALL(X, SYS_SENTRY, sentry)                       \
  M_IRQ(X, IRQ_EXT, 9)                                   \
  M_EXC(X, EXC_INST_PF, trap::EXC_INST_PAGE_FAULT)       \
  M_EXC(X, EXC_LOAD_PF, trap::EXC_LOAD_PAGE_FAULT)       \
  M_EXC(X, EXC_STORE_PF, trap::EXC_STORE_PAGE_FAULT)     \
  M_EXC(X, EXC_CHERI, trap::EXC_CHERI)                   \
  M_MMIO(X, PLIC_MMIO, "plic")                           \
  M_SERVICE(X, UART_SENTRY, "uart")
SIGNETOS_MANIFEST(TRAP_MGR_MANIFEST, 64 * 1024)
// Runtime slots: the two entry points minted in the handshake.
constexpr size_t SLOT_IRQ_ROUTE_ENTRY = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 0;
constexpr size_t SLOT_IRQ_ENTRY       = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 1;

constexpr size_t MAX_ROUTES = 8;

struct Route {
  uint32_t source;  // 0 = free
  uint32_t count;
  Capability handlers[init::IRQ_MAX_HANDLERS];
};

// Compartment state, in our own image (.bss).
alignas(16) Route s_routes[MAX_ROUTES];
Capability s_plic = nullptr;  // the delegated window (Load|Store)
Capability s_gate_invoke = nullptr;
uint64_t s_context = 0;  // the PLIC context devices interrupt (WHICH HART)
uint32_t s_ndev = platform::DEFAULT_PLIC_NDEV;
bool s_online = false;

// The number of the hart this is running on. The kernel leaves it in `utidc`
// as a plain integer, no authority in it, and reading it needs none.
uint64_t this_hart() {
  Capability id;
  __asm__ volatile("csrr %0, 0x480" : "=C"(id));  // 0x480 = utidc
  return capability_get_address(id);
}

// --- PLIC --------------------------------------------------------------------
// 32-bit registers; offsets from platform.hpp, context = `s_context`.

volatile uint32_t* plic_reg(uint64_t offset) {
  return reinterpret_cast<volatile uint32_t*>(
      capability_set_address(s_plic, capability_get_base(s_plic) + offset));
}

volatile uint32_t* plic_enable_word(uint32_t source) {
  return plic_reg(platform::PLIC_ENABLE_BASE +
                  s_context * platform::PLIC_ENABLE_STRIDE + 4 * (source / 32));
}

volatile uint32_t* plic_claim() {
  return plic_reg(platform::PLIC_CONTEXT_BASE +
                  s_context * platform::PLIC_CONTEXT_STRIDE +
                  platform::PLIC_CLAIM_OFFSET);
}

void plic_set_threshold(uint32_t threshold) {
  *plic_reg(platform::PLIC_CONTEXT_BASE +
            s_context * platform::PLIC_CONTEXT_STRIDE) = threshold;
}

void plic_enable(uint32_t source) {
  *plic_reg(platform::PLIC_PRIORITY + 4 * source) = 1;  // lowest non-zero
  volatile uint32_t* word = plic_enable_word(source);
  *word = *word | (1u << (source % 32));
}

void plic_disable(uint32_t source) {
  volatile uint32_t* word = plic_enable_word(source);
  *word = *word & ~(1u << (source % 32));
}

// --- Routes ------------------------------------------------------------------

Route* find_route(uint32_t source) {
  for (Route& r : s_routes) {
    if (r.source == source) {
      return &r;
    }
  }
  return nullptr;
}

Route* alloc_route(uint32_t source) {
  for (Route& r : s_routes) {
    if (r.source == 0) {
      r.count = 0;
      r.source = source;
      return &r;
    }
  }
  return nullptr;
}

}  // namespace

// --- Entry points
// --------------------------------------------------------------

extern "C" void trap_mgr_irq_route_entry(Capability arg) {
  if (!capability_is_valid(arg) || sealing::is_sealed(arg) ||
      !capability_has_perms(arg, perms::Load | perms::Store) ||
      capability_get_length(arg) < sizeof(init::IrqRouteRequest)) {
    return;
  }
  Capability* rw = rw_table();
  Capability gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  Capability uart_sentry = rw[SLOT_UART_SENTRY];
  // print(gate_invoke, uart_sentry, "[trap_mgr] Interrupt routed\n");
  auto* req = reinterpret_cast<init::IrqRouteRequest*>(arg);
  req->status = init::IRQ_BAD_REQUEST;
  if (!s_online || req->source == 0 || req->source > s_ndev ||
      !sealing::is_sealed_as(OType::EntryPoint, req->handler)) {
    return;
  }
  const auto source = static_cast<uint32_t>(req->source);
  Route* r = find_route(source);
  if (r == nullptr) {
    r = alloc_route(source);
    if (r == nullptr) {
      req->status = init::IRQ_FULL;
      return;
    }
  }
  for (uint32_t i = 0; i < r->count; ++i) {
    if (capability_get_address(r->handlers[i]) ==
        capability_get_address(req->handler)) {
      req->status = init::IRQ_OK;  // already routed
      return;
    }
  }
  if (r->count == init::IRQ_MAX_HANDLERS) {
    req->status = init::IRQ_FULL;
    return;
  }
  // Handler in place before the count admits it, and the source enabled
  // only after that: the interrupt handler can land between any two of these
  // stores and must never see a route with a hole in it.
  r->handlers[r->count] = req->handler;
  __asm__ volatile("" ::: "memory");
  r->count += 1;
  if (r->count == 1) {
    plic_enable(source);
  }
  req->status = init::IRQ_OK;
}

// IRQ_S_EXT handler (kernel trap ABI: a0-a3 = scause/stval/sepc/stval2,
// ca4 = this compartment's capability table). Runs masked on the interrupted
// thread's stack; `cgp` is our table, so globals resolve as usual.
extern "C" void trap_mgr_irq_entry(uint64_t scause, uint64_t stval,
                                   uint64_t sepc, uint64_t stval2,
                                   Capability cap_table_rw) {
  (void)scause;
  (void)stval;
  (void)sepc;
  (void)stval2;
  (void)cap_table_rw;
  if (!capability_is_valid(s_plic)) {
    return;
  }
  Capability* rw = rw_table();
  Capability gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  Capability uart_sentry = rw[SLOT_UART_SENTRY];
  // print(gate_invoke, uart_sentry, "[trap_mgr] Interrupt routed\n");

  using FnInvoke = decltype(&sys_compartment_invoke);
  auto invoke = reinterpret_cast<FnInvoke>(s_gate_invoke);
  volatile uint32_t* claim = plic_claim();
  for (;;) {
    const uint32_t source = *claim;  // highest-priority pending source, or 0
    if (source == 0) {
      break;
    }
    Route* r = find_route(source);
    if (r == nullptr) {
      plic_disable(source);  // nobody asked for it; do not let it storm
    } else {
      alignas(16) init::IrqEvent event{};
      event.source = source;
      Capability ev = reinterpret_cast<Capability>(&event);
      ev = capability_set_bounds(ev, sizeof(event));
      ev = capability_and_perms(ev, perms::Load);
      for (uint32_t i = 0; i < r->count; ++i) {
        invoke(r->handlers[i], ev);
      }
    }
    *claim = source;  // complete: the source may raise again
  }
}

extern "C" void compartment_main(Capability arg) {
  Capability* rw = rw_table();

  Capability self_comp = rw[compartment::SLOT_SELF];
  Capability vm_quota = rw[compartment::SLOT_VM_QUOTA];

  Capability gate_trap_bind = rw[SLOT_SYS_TRAP_BIND];
  Capability gate_sentry = rw[SLOT_SYS_SENTRY];
  Capability irq_ext = rw[SLOT_IRQ_EXT];
  Capability exc_inst_pf = rw[SLOT_EXC_INST_PF];
  Capability exc_load_pf = rw[SLOT_EXC_LOAD_PF];
  Capability exc_store_pf = rw[SLOT_EXC_STORE_PF];
  Capability exc_cheri = rw[SLOT_EXC_CHERI];
  Capability plic = rw[SLOT_PLIC_MMIO];
  Capability gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  Capability uart_sentry = rw[SLOT_UART_SENTRY];

  if (!sealing::is_sealed_as(OType::Compartment, self_comp) ||
      !sealing::is_sealed_as(OType::QuotaVm, vm_quota) ||
      !sealing::is_sealed_as(OType::Trap, irq_ext) ||
      !sealing::is_sealed_as(OType::Trap, exc_inst_pf) ||
      !sealing::is_sealed_as(OType::Trap, exc_load_pf) ||
      !sealing::is_sealed_as(OType::Trap, exc_store_pf) ||
      !sealing::is_sealed_as(OType::Trap, exc_cheri) ||
      !capability_is_valid(plic) ||
      !capability_has_perms(plic, perms::Load | perms::Store)) {
    return;
  }

  // `init`'s handshake, or nothing (a probe). Either way the setup below
  // happens once, and `irq_route` goes to the first caller and never again:
  // the right to decide which driver a device reaches is `init`'s alone.
  init::TrapMgrInterface* iface = nullptr;
  if (capability_is_valid(arg) && !sealing::is_sealed(arg) &&
      capability_has_perms(arg, perms::Load | perms::Store) &&
      capability_get_length(arg) == sizeof(init::TrapMgrInterface)) {
    iface = reinterpret_cast<init::TrapMgrInterface*>(arg);
    iface->irq_route = nullptr;
  }
  if (s_online) {
    return;
  }

  // Devices interrupt the hart this runs on, the one the system booted on
  // (WHICH HART). `init` passes the DTB-discovered S-mode PLIC context map
  // and `riscv,ndev` in `TrapMgrInterface`.
  const uint64_t hart = this_hart();
  if (hart >= platform::MAX_HARTS) {
    return;
  }
  uint32_t ctx = static_cast<uint32_t>(2 * hart + 1);
  uint32_t ndev = platform::DEFAULT_PLIC_NDEV;
  if (iface != nullptr && iface->plic_ndev != 0) {
    ctx = iface->plic_s_context[hart];
    ndev = (iface->plic_ndev > platform::PLIC_MAX_SOURCE)
               ? platform::PLIC_MAX_SOURCE
               : iface->plic_ndev;
  }
  if (ctx == platform::PLIC_NO_CONTEXT ||
      capability_get_length(plic) < platform::plic_window_for_context(ctx)) {
    return;
  }

  s_plic = plic;
  s_gate_invoke = gate_invoke;
  s_context = ctx;
  s_ndev = ndev;
  for (Route& r : s_routes) {
    r.source = 0;
    r.count = 0;
  }

  // This hart's S-mode context: let every priority through. Firmware leaves
  // the threshold at its maximum, which blocks everything; sources stay off
  // until something is routed to them.
  plic_set_threshold(0);

  Capability e_route =
      mint_entry(gate_invoke, gate_sentry, self_comp,
                 reinterpret_cast<const void*>(&trap_mgr_irq_route_entry));
  Capability e_irq =
      mint_entry(gate_invoke, gate_sentry, self_comp,
                 reinterpret_cast<const void*>(&trap_mgr_irq_entry));
  if (!sealing::is_sealed_as(OType::EntryPoint, e_route) ||
      !sealing::is_sealed_as(OType::EntryPoint, e_irq)) {
    return;
  }
  rw[SLOT_IRQ_ROUTE_ENTRY] = e_route;
  rw[SLOT_IRQ_ENTRY] = e_irq;

  // Bind code 9. The kernel sets `sie.SEIE` on every hart; from now on any
  // source we enable at the PLIC lands in `trap_mgr_irq_entry`.
  using FnTrapBind = decltype(&sys_trap_bind);
  syscall::call<FnTrapBind>(gate_invoke, gate_trap_bind, self_comp, irq_ext,
                            e_irq);
  s_online = true;

  if (iface != nullptr) {
    iface->irq_route = e_route;
  }
  print_dec(gate_invoke, uart_sentry, "[trap_mgr] PLIC online (hart ", hart,
            " S-mode context, threshold 0); IRQ_S_EXT bound; routes via "
            "irq_route\n");
}

}  // namespace signetos::user
