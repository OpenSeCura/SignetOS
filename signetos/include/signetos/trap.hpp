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
// trap.hpp - SignetOS Hardware Trap and Interrupt Binding Subsystem
//
// SEALED TRAP AUTHORITIES (OType::Trap, CT = 13)
// ----------------------------------------------
// Each hardware trap vector (synchronous exceptions 0..31 and asynchronous
// interrupts 0..15) has a dedicated slot in the kernel's static trap table.
// At boot, `trap::authority_for(scause)` mints a sealed `OType::Trap` handle
// bounded to that vector's `TrapSlot` with `Permit_Load | Permit_Store`.
//
// Holding a sealed `OType::Trap` capability with `Permit_Load` authorizes
// binding (`sys_trap_bind`) and unbinding (`sys_trap_unbind`) a compartment
// `OType::EntryPoint` (CT = 12) sentry to that hardware vector.
//
// When a bound trap or interrupt fires:
//   1. `_early_trap_entry` saves all 31 capability registers (`cra`, `csp`,
//      `cgp`, `ctp`, `ct0`..`ct6`, `cs0`..`cs11`, `ca0`..`ca7`), `sepcc`, and
//      the hart's `sscratchc` kernel SP into a 592-byte `TrapFrame` on the
//      active kernel stack.
//   2. `__signetos_trap_dispatch` looks up the vector and resolves the bound
//      `OType::EntryPoint` into a `CT = 1` hardware sentry. The handler
//      runs below the interrupted `csp`, narrowed by the same stack rule as
//      a callee's (`sentry::narrow_stack`: permissions including StoreLocal,
//      the handler's `min_stack` free, exactly representable, never the
//      kernel stack), and makes its kernel calls on the interrupted kernel
//      stack, which must have `RET_FRAME_MIN_FREE` below the `TrapFrame`.
//      A thread that fails either cannot take a trap, so cannot be
//      preempted, and is ended there (`trap.cpp`, `end_interrupted_thread`).
//   3. The handler sentry is invoked with `(scause, stval, sepc, stval2,
//      cap_table)` in `(a0, a1, a2, a3, ca4)` (with `cgp = ca4`) and all
//      other registers scrubbed to `cnull`.
//   4. Because `sscratchc` points to the `TrapFrame` while the handler runs,
//      the handler may freely invoke syscalls or call `sys_thread_switch` to
//      preempt the interrupted thread. An interrupt handler runs with
//      interrupts masked. An exception handler runs with the interrupted
//      code's `SIE`, so over thread code an interrupt can be handled on top
//      of it and return into it (asm_macros.h, INTERRUPT MASKING RULE).
//   5. When the handler returns, the kernel scrubs the handler's narrowed
//      stack, and `_early_trap_entry` restores `sepcc` and all 31 capability
//      registers from the `TrapFrame` and executes `sret`.
//
// A synchronous fault raised by kernel code (`sepcc` with AccessSystemRegs)
// is never delivered to a handler: it is a kernel bug and halts the machine.
//
// THE KERNEL TICK
// ---------------
// The kernel owns the supervisor timer. Binding `IRQ_S_TIMER` arms a fixed
// periodic tick (`TICK_US`) on every hart; before every delivery to the bound
// handler the kernel re-arms that hart's next tick, so the handler only ever
// observes the interrupt (no syscall exists to program the timer). Unbinding,
// or a tick arriving with nothing bound, disarms it.
//
// OTHER INTERRUPTS
// ----------------
// Every other interrupt vector is gated by its `sie` bit alone: the bit is
// set while the slot is bound and clear while it is not, and an interrupt
// that arrives unbound has its bit cleared on the spot. The kernel does
// nothing device-specific. In particular `IRQ_S_EXT` (code 9) is the single
// wire every PLIC device shares; the PLIC itself is a device window delegated
// to the compartment that binds code 9 (`trap_mgr`), and claiming and
// completing the source there -- which is what drops the level-triggered
// interrupt -- is that handler's job. The handler runs masked, so a source
// that is not claimed simply fires again at the next `sret`.
//
// SEVERAL HARTS
// -------------
// `sie` and the timer belong to a hart, and a hart can only change its own.
// So each hart keeps its own `sie` and timer in line with the one trap table
// (`sync_all_harts`): a system call that changes the table brings its own
// hart in line and then pokes every other hart, which brings itself in line
// when the poke arrives. Which hart a device interrupt is sent to is not
// decided here: that is a PLIC setting, and `trap_mgr` owns the PLIC.
//
// THE SOFTWARE INTERRUPT IS THE KERNEL'S
// --------------------------------------
// The poke is the supervisor software interrupt (`IRQ_S_SOFT`), sent with
// the SBI IPI call (`sbi::send_ipi`). It is the only way one hart can
// interrupt another, and it carries no message, so it cannot be shared: if a
// compartment could bind it, the kernel could not tell its own pokes from
// the compartment's. No authority is minted for it (`authority_for` returns
// null), its `sie` bit is always set, and the dispatcher handles it itself.
//

#include <stddef.h>
#include <stdint.h>
#include <signetos/types.hpp>

namespace signetos::trap {

constexpr uint64_t INTERRUPT_BIT = (1ULL << 63);

// Standard RISC-V synchronous exception codes (scause with bit 63 == 0).
constexpr uint64_t EXC_INST_MISALIGNED  = 0;
constexpr uint64_t EXC_INST_ACCESS      = 1;
constexpr uint64_t EXC_ILLEGAL_INST     = 2;
constexpr uint64_t EXC_BREAKPOINT       = 3;
constexpr uint64_t EXC_LOAD_MISALIGNED  = 4;
constexpr uint64_t EXC_LOAD_ACCESS      = 5;
constexpr uint64_t EXC_STORE_MISALIGNED = 6;
constexpr uint64_t EXC_STORE_ACCESS     = 7;
constexpr uint64_t EXC_ECALL_U          = 8;
constexpr uint64_t EXC_ECALL_S          = 9;
constexpr uint64_t EXC_INST_PAGE_FAULT  = 12;
constexpr uint64_t EXC_LOAD_PAGE_FAULT  = 13;
constexpr uint64_t EXC_STORE_PAGE_FAULT = 15;
constexpr uint64_t EXC_CHERI            = 28;

// Standard RISC-V S-mode interrupt causes (scause with bit 63 == 1).
constexpr uint64_t IRQ_S_SOFT  = INTERRUPT_BIT | 1;
constexpr uint64_t IRQ_S_TIMER = INTERRUPT_BIT | 5;
constexpr uint64_t IRQ_S_EXT   = INTERRUPT_BIT | 9;

// Period of the kernel tick delivered to the `IRQ_S_TIMER` handler.
constexpr uint64_t TICK_US = 10'000;

constexpr size_t MAX_EXCEPTION_VECTORS = 32;
constexpr size_t MAX_INTERRUPT_VECTORS = 16;
constexpr size_t MAX_TRAP_SLOTS =
    MAX_EXCEPTION_VECTORS + MAX_INTERRUPT_VECTORS;

using Status = signetos::Status;
using signetos::status_name;

// Saved context pushed onto the active kernel stack by `_early_trap_entry`
// before dispatching a trap or interrupt.
struct alignas(16) TrapFrame {
  Capability ra;                //   0
  Capability sp;                //  16
  Capability gp;                //  32
  Capability tp;                //  48
  Capability t[7];              //  64..160
  Capability s[12];             // 176..352
  Capability a[8];              // 368..480
  Capability active_kernel_sp;  // 496
  Capability sepcc;             // 512
  Capability handler_sp;        // 528 (populated by __signetos_trap_dispatch)
  Capability handler_rw_table;  // 544 (populated by __signetos_trap_dispatch)
  // Both populated by __signetos_trap_dispatch for a handler it delivers
  // (asm_macros.h, INTERRUPT MASKING RULE):
  uint64_t sstatus;             // 560 `sstatus` at entry; its SPIE is the
                                //     interrupted code's SIE
  uint64_t handler_sie;         // 568 SSTATUS_SIE if the handler runs with
                                //     interrupts enabled, else 0
};

static_assert(sizeof(TrapFrame) == 36 * sizeof(Capability),
              "TrapFrame must be 35 capabilities and two integers (576 "
              "bytes)");

// One routing entry per supported `scause`; the slot index encodes the cause.
// `owner_comp_uid == 0` means unbound. The uid is kept alongside the handle so
// a binding left behind by a destroyed compartment is refused.
//
// Only system calls (`bind`, `unbind`, `purge_compartment`) write a slot; the
// trap dispatcher only reads. A writer bumps `seq` to odd before touching the
// other fields and back to even after; a reader copies the slot and accepts
// the copy only if `seq` was even and unchanged across the copy (`read_slot`).
// So a reader never acts on a half-written slot and never waits -- what the
// trap path needs once writers can run on another hart.
struct alignas(16) TrapSlot {
  Capability owner_comp;
  Capability target_sentry;
  uint64_t owner_comp_uid;
  uint64_t seq;
};

// Clears the static trap routing table.
void init();

// Per-hart initialisation: turns on this hart's poke bit, turns its timer
// off, adds the hart to the ones that pokes are sent to, and brings its
// `sie` and timer in line with the trap table. Every hart calls it once, on
// itself, after `thread::init_hart` (and the boot hart, whichever hart
// OpenSBI started, after `init`).
void init_hart();

// Brings every hart's `sie` and timer in line with the trap table: this hart
// now, every other hart when the poke this sends arrives. `bind`, `unbind`
// and `purge_compartment` call it after changing the table.
void sync_all_harts();

// Returns the sealed `OType::Trap` (CT = 13) authority handle for `scause`,
// or `nullptr` if `scause` is outside the supported vector range or is
// `IRQ_S_SOFT`, which nobody may bind (THE SOFTWARE INTERRUPT IS THE
// KERNEL'S, above).
Capability authority_for(uint64_t scause);

// Convenience wrappers for minting exception or interrupt authorities.
inline Capability exception_authority(uint64_t exc_code) {
  return (exc_code < MAX_EXCEPTION_VECTORS) ? authority_for(exc_code) : nullptr;
}

inline Capability irq_authority(uint64_t irq_code) {
  return (irq_code < MAX_INTERRUPT_VECTORS)
             ? authority_for(INTERRUPT_BIT | irq_code)
             : nullptr;
}

// Core of `sys_trap_bind`. Authenticates `comp` (OType::Compartment),
// `auth_cap` (OType::Trap with Permit_Load), and `target_sentry`
// (OType::EntryPoint with Permit_Load), then binds `target_sentry` to the
// vector named by `auth_cap`, tagged with `comp`'s UID.
Status bind(Capability comp, Capability auth_cap, Capability target_sentry);

// Core of `sys_trap_unbind`. Authenticates `comp` and `auth_cap`, verifies
// that the vector is currently bound to `comp`, and clears the binding.
Status unbind(Capability comp, Capability auth_cap);

// Called by `compartment::destroy` to purge any trap bindings owned by the
// compartment with `comp_uid`.
size_t purge_compartment(uint64_t comp_uid);

// Diagnostics for tests.
bool is_bound(uint64_t scause, uint64_t* out_owner_uid = nullptr);
size_t bound_count();

}  // namespace signetos::trap
