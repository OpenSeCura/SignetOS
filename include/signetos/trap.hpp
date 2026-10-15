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
// SEALED TRAP AUTHORITIES (OType::Trap, CT = 19)
// ----------------------------------------------
// Each asynchronous interrupt vector (0..15) has a dedicated slot in the
// kernel's static trap table. At boot, `trap::authority_for(mcause)` mints a
// sealed `OType::Trap` handle bounded to that vector's `TrapSlot` with
// `Permit_Load | Permit_Store`.
//
// Holding a sealed `OType::Trap` capability with `Permit_Load` authorizes
// binding (`sys_trap_bind`) and unbinding (`sys_trap_unbind`) a compartment
// `OType::EntryPoint` (CT = 18) sentry to that interrupt vector.
//
// Synchronous exceptions (0..31) are NOT bindable: no authority is minted
// for them and `bind` refuses their slots. A fault is handled by the
// compartment that raised it, through the fault handler it installed in its
// own descriptor (fault.hpp, PER-COMPARTMENT FAULTS below).
//
// Everything runs in M-mode and nothing is delegated, so every trap is taken
// in M-mode, by the kernel. When a bound interrupt fires, or compartment code
// faults:
//   1. `_early_trap_entry` saves all 31 capability registers (`cra`, `csp`,
//      `cgp`, `ctp`, `ct0`..`ct6`, `cs0`..`cs11`, `ca0`..`ca7`), `mepcc`, and
//      the hart's `mscratchc` kernel SP into a 640-byte `TrapFrame` on the
//      active kernel stack.
//   2. `__signetos_trap_dispatch` picks the handler -- the vector's bound
//      `OType::EntryPoint`, or the faulting compartment's fault handler --
//      as a `CT = 1` hardware sentry. The handler runs below the interrupted
//      `csp`, narrowed by the same stack rule as a callee's
//      (`sentry::narrow_stack`: permissions including StoreLocal, the
//      handler's `min_stack` free, exactly representable, never the kernel
//      stack), and makes its kernel calls on the interrupted kernel stack,
//      which must have `RET_FRAME_MIN_FREE` below the `TrapFrame`. An
//      interrupted thread that fails either cannot be preempted and is ended
//      there (`trap.cpp`, `end_interrupted_thread`); a fault that fails
//      either is reported and unwound instead of delivered.
//   3. The handler sentry is invoked with `(ca0, mtval, mepc, mtval2,
//      cap_table)` in `(ca0, a1, a2, a3, ca4)` (with `cgp = ca4`) and all
//      other registers scrubbed to `cnull`. For an interrupt `ca0` is the
//      integer `mcause`; for a fault it is the compartment's ErrorState
//      (fault.hpp), at the top of the handler's stack.
//   4. Because `mscratchc` points to the `TrapFrame` while the handler runs,
//      the handler may freely invoke syscalls or call `sys_thread_switch` to
//      preempt the interrupted thread. An interrupt handler runs with
//      interrupts masked. A fault handler runs with the interrupted code's
//      `MIE`, so over thread code an interrupt can be handled on top of it
//      and return into it (asm_macros.h, INTERRUPT MASKING RULE).
//   5. When the handler returns, the kernel scrubs the handler's narrowed
//      stack and pops the `TrapFrame` (`__signetos_trap_return` =
//      `unwind::resume`). An interrupted context is always resumed; a
//      faulting one only on the handler's INSTALL_CONTEXT verdict, with the
//      register file it left in the ErrorState, and otherwise unwound: the
//      frame beneath gets `Status::Faulted` in a0. `_early_trap_entry` then
//      restores `mepcc` and all 31 capability registers of whatever frame it
//      stopped at and executes `mret` (or returns through the switcher).
//
// PER-COMPARTMENT FAULTS
// ----------------------
// The faulting compartment is named by the frame directly beneath the
// fault's `TrapFrame`, never by anything the compartment controls (its
// `cgp`, its table): a `ReturnFrame`'s `callee_comp` (the canonical handle
// the switcher recorded from the entry record), a `TrapFrame`'s
// `handler_comp` (if that frame is itself a fault frame, the fault was in a
// fault handler: never delivered again, it unwinds), or, at the bottom of a
// thread, the owner of the thread's entry sentry. `compartment::open` then
// checks that compartment is still live.
//
// A synchronous fault raised by kernel code (`mepcc` with AccessSystemRegs)
// is never delivered to a handler: it is a kernel bug and halts the machine.
//
// THE KERNEL TICK
// ---------------
// The kernel owns the machine timer, which it drives itself through the
// CLINT (clint.hpp). Binding `IRQ_M_TIMER` arms a fixed periodic tick
// (`TICK_US`) on every hart; before every delivery to the bound handler the
// kernel re-arms that hart's next tick, so the handler only ever observes
// the interrupt (no syscall exists to program the timer). Unbinding, or a
// tick arriving with nothing bound, disarms it.
//
// OTHER INTERRUPTS
// ----------------
// Every other interrupt vector is gated by its `mie` bit alone: the bit is
// set while the slot is bound and clear while it is not, and an interrupt
// that arrives unbound has its bit cleared on the spot. The kernel does
// nothing device-specific. In particular `IRQ_M_EXT` (code 11) is the single
// wire every PLIC device shares; the PLIC itself is a device window delegated
// to the compartment that binds code 11 (`trap_mgr`), and claiming and
// completing the source there -- which is what drops the level-triggered
// interrupt -- is that handler's job. The handler runs masked, so a source
// that is not claimed simply fires again at the next `mret`.
//
// SEVERAL HARTS
// -------------
// `mie` and the timer belong to a hart, and a hart can only change its own.
// So each hart keeps its own `mie` and timer in line with the one trap table
// (`sync_all_harts`): a system call that changes the table brings its own
// hart in line and then pokes every other hart, which brings itself in line
// when the poke arrives. Which hart a device interrupt is sent to is not
// decided here: that is a PLIC setting, and `trap_mgr` owns the PLIC.
//
// THE SOFTWARE INTERRUPT IS THE KERNEL'S
// --------------------------------------
// The poke is the machine software interrupt (`IRQ_M_SOFT`), sent by setting
// the target hart's CLINT `msip` (`clint::send_ipi`). It is the only way one
// hart can interrupt another, and it carries no message, so it cannot be
// shared: if a compartment could bind it, the kernel could not tell its own
// pokes from the compartment's. No authority is minted for it
// (`authority_for` returns null), its `mie` bit is always set, and the
// dispatcher handles it itself.
//

#include <stddef.h>
#include <stdint.h>
#include <signetos/types.hpp>

namespace signetos::trap {

constexpr uint64_t INTERRUPT_BIT = (1ULL << 63);

// Standard RISC-V synchronous exception codes (mcause with bit 63 == 0).
// Everything runs in M-mode, so an `ecall` is always EXC_ECALL_M.
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
constexpr uint64_t EXC_ECALL_M          = 11;
constexpr uint64_t EXC_INST_PAGE_FAULT  = 12;
constexpr uint64_t EXC_LOAD_PAGE_FAULT  = 13;
constexpr uint64_t EXC_STORE_PAGE_FAULT = 15;
constexpr uint64_t EXC_CHERI            = 28;

// Standard RISC-V M-mode interrupt causes (mcause with bit 63 == 1).
constexpr uint64_t IRQ_M_SOFT  = INTERRUPT_BIT | 3;
constexpr uint64_t IRQ_M_TIMER = INTERRUPT_BIT | 7;
constexpr uint64_t IRQ_M_EXT   = INTERRUPT_BIT | 11;

// Period of the kernel tick delivered to the `IRQ_M_TIMER` handler.
constexpr uint64_t TICK_US = 10'000;

constexpr size_t MAX_EXCEPTION_VECTORS = 32;
constexpr size_t MAX_INTERRUPT_VECTORS = 16;
constexpr size_t MAX_TRAP_SLOTS =
    MAX_EXCEPTION_VECTORS + MAX_INTERRUPT_VECTORS;

using Status = signetos::Status;
using signetos::status_name;

// `TrapFrame::flags`. Bit 1 is sentry::ENTRY_FLAG_TRUSTED_TO_FINISH, so the
// unwinder tests the same bit on either kind of frame.
//
// TRAP_FLAG_FAULT marks a frame pushed for a fault in compartment code
// (fault.hpp): whether a handler was delivered on it or not, it is resumed
// only on its handler's INSTALL_CONTEXT verdict, and otherwise skipped, the
// frame beneath getting `fault_status`. A fault taken while the frame
// beneath is such a frame is a fault in a fault handler, and is never
// delivered.
constexpr uint64_t TRAP_FLAG_FAULT = 1u << 4;

// Saved context pushed onto the active kernel stack by `_early_trap_entry`
// before dispatching a trap or interrupt.
struct alignas(16) TrapFrame {
  Capability ra;                //   0
  Capability sp;                //  16
  Capability gp;                //  32
  Capability active_kernel_sp;  //  48 FRAME LINK (asm_macros.h), written
                                //     by the trap vector at push
  Capability t[7];              //  64..160
  Capability s[12];             // 176..352
  Capability a[8];              // 368..480
  Capability tp;                // 496
  Capability mepcc;             // 512
  Capability handler_sp;        // 528 (populated by __signetos_trap_dispatch)
  Capability handler_rw_table;  // 544 (populated by __signetos_trap_dispatch)
  // Both populated by __signetos_trap_dispatch for a handler it delivers
  // (asm_macros.h, INTERRUPT MASKING RULE):
  uint64_t mstatus;             // 560 `mstatus` at entry; its MPIE is the
                                //     interrupted code's MIE
  uint64_t handler_mie;         // 568 MSTATUS_MIE if the handler runs with
                                //     interrupts enabled, else 0
  uint64_t flags;               // 576 TRAP_FLAG_* above, and
                                //     ENTRY_FLAG_TRUSTED_TO_FINISH if the
                                //     handler's compartment is trusted to
                                //     finish (unwind.hpp, KILLED THREADS)
  uint64_t fault_status;        // 584 a fault frame: the `Status` the frame
                                //     beneath gets if this one is skipped
                                //     (Faulted, or CompartmentDestroyed)
  Capability handler_comp;      // 592 the delivered handler's compartment
                                //     handle; null if none was delivered
                                //     (WHO FAULTED)
  // The handler's ca0 and a3, written by __signetos_trap_dispatch (a1 and a2
  // are always mtval and mepc, read from the CSRs): for an interrupt the
  // integer `mcause` and `mtval2`; for a fault its ErrorState (fault.hpp) and
  // `mtval2`.
  Capability handler_ca0;       // 608
  uint64_t handler_a3;          // 624
  uint64_t reserved_;           // 632 (keeps the frame a capability multiple)
};

static_assert(sizeof(TrapFrame) == 40 * sizeof(Capability),
              "TrapFrame must be 37 capabilities and six integers (640 "
              "bytes)");

// One routing entry per supported `mcause`; the slot index encodes the cause.
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
// off, clears any poke left pending, adds the hart to the ones that pokes are
// sent to, and brings its `mie` and timer in line with the trap table. Every
// hart calls it once, on itself, after `thread::init_hart` (and the boot
// hart, whichever hart won the boot lottery in boot.S, after `init`).
void init_hart();

// Brings every hart's `mie` and timer in line with the trap table: this hart
// now, every other hart when the poke this sends arrives. `bind`, `unbind`
// and `purge_compartment` call it after changing the table.
void sync_all_harts();

// Returns the sealed `OType::Trap` (CT = 19) authority handle for `mcause`,
// or `nullptr` if `mcause` is outside the supported vector range, is an
// exception (PER-COMPARTMENT FAULTS, above), or is `IRQ_M_SOFT`, which
// nobody may bind (THE SOFTWARE INTERRUPT IS THE KERNEL'S, above).
Capability authority_for(uint64_t mcause);

// Convenience wrapper for minting interrupt authorities.
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

// The fault handler delivered on fault frame `frame` returned INSTALL_CONTEXT
// (fault.hpp): loads `frame`'s registers from the ErrorState the handler
// left, and its `mepcc` from the faulting PCC re-addressed to the
// ErrorState's `pc`. False, with `frame` untouched, if there is no
// ErrorState or the new `mepcc` is not a valid capability; the frame is then
// unwound as for any other verdict (unwind.cpp).
bool install_context(TrapFrame* frame);

// Diagnostics for tests.
bool is_bound(uint64_t mcause, uint64_t* out_owner_uid = nullptr);
size_t bound_count();

}  // namespace signetos::trap
