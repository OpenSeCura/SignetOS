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
 * boot.S - SignetOS CHERI RISC-V Pure-Capability Kernel Bootloader
 *
 * Every hart starts here in M-mode and never leaves it: the kernel and all
 * compartments run in M-mode, the CHERI ASR permission is the only privilege
 * boundary, and `mmodemmu` (toolchain/mmodemmu) lets M-mode use the MMU.
 *
 * Boot sequence:
 * 1. Switch CPU hardware to Pure Capability Pointer Mode (modesw.cap, PCC.P = 0).
 * 2. Derive master root data capability (cs11) and code capability (cs10) from PCC.
 * 3. Save Boot Hart ID (cs0 = ca0) and derive Device Tree Blob capability (cs2).
 * 4. Set up tightly-bounded, non-executable stack capability (csp).
 * 5. Set up Capability Global Pointer (cgp) to .got.
 * 6. Process __cap_relocs table to dynamically seal/relocate all capability pointers in GOT/data.
 * 7. Zero-initialize the .bss section using the root data capability.
 * 8. Set up the machine trap vector capability (mtvecc).
 * 9. Jump to the C++ kernel entry: kernel_main(root_data_cap, hartid, dtb_cap).
 */

/*
 * Architectural permission masks for kernel capabilities constructed at boot:
 *   - KERNEL_CODE_PERMS:     Read | Execute | Capability | LoadMutable | ASR
 *                            (strips Store, Seal, Unseal; enforces W^X on PCC)
 *   - KERNEL_RO_TABLE_PERMS: Read | Capability | LoadMutable
 *                            (for cgp covering .got; read-only after boot.S)
 *   - KERNEL_RODATA_PERMS:   Read | Capability
 *                            (for CONSTANT_REL .rodata objects; strips Store)
 *   - KERNEL_DATA_PERMS:     Read | Write | Capability | LoadMutable
 *                            (for stacks and writable .data/.bss objects;
 *                            strips Execute, Seal, Unseal, and ASR)
 *
 * Every mask also keeps KERNEL_LEVEL_PERMS, the three Zylevels1 bits
 * (`perms::Levels` in types.hpp is the C++ twin):
 *   Global (GL)      -- the capability stays global (1) rather than local (0)
 *   LoadGlobal (LG)  -- loads through it do not relabel loaded caps as local
 *   StoreLocal (SL)  -- stores through it keep the tag of local caps
 * The roots carry all three. acperm keeps only the bits in its mask, so a
 * mask without them would make PCC, csp and every derived kernel capability
 * local and strip SL from csp; the first `csc cra` of a prologue would then
 * store an untagged return address and the matching `ret` would fault. On a
 * hart without Zylevels1 the bits read as ones and cannot be cleared, so
 * keeping them costs nothing there.
 */
#ifdef __CHERI_CAP_PERMISSION_CAPABILITY_LEVEL__
#define KERNEL_LEVEL_PERMS \
    (__CHERI_CAP_PERMISSION_CAPABILITY_LEVEL__ | \
     __CHERI_CAP_PERMISSION_ELEVATE_LEVEL__ | \
     __CHERI_CAP_PERMISSION_STORE_LEVEL__)
#else
/* -march lacks zcherilevels, so the toolchain does not define the macros; the
 * ISA bit positions are fixed: GL = bit 4, LG = bit 2, SL = bit 3. */
#define KERNEL_LEVEL_PERMS ((1 << 4) | (1 << 2) | (1 << 3))
#endif

#define KERNEL_CODE_PERMS \
    (__CHERI_CAP_PERMISSION_READ__ | \
     __CHERI_CAP_PERMISSION_EXECUTE__ | \
     __CHERI_CAP_PERMISSION_CAPABILITY__ | \
     __CHERI_CAP_PERMISSION_LOAD_MUTABLE__ | \
     __CHERI_CAP_PERMISSION_ACCESS_SYSTEM_REGISTERS__ | \
     KERNEL_LEVEL_PERMS)

#define KERNEL_RO_TABLE_PERMS \
    (__CHERI_CAP_PERMISSION_READ__ | \
     __CHERI_CAP_PERMISSION_CAPABILITY__ | \
     __CHERI_CAP_PERMISSION_LOAD_MUTABLE__ | \
     KERNEL_LEVEL_PERMS)

#define KERNEL_RODATA_PERMS \
    (__CHERI_CAP_PERMISSION_READ__ | \
     __CHERI_CAP_PERMISSION_CAPABILITY__ | \
     KERNEL_LEVEL_PERMS)

#define KERNEL_DATA_PERMS \
    (__CHERI_CAP_PERMISSION_READ__ | \
     __CHERI_CAP_PERMISSION_WRITE__ | \
     __CHERI_CAP_PERMISSION_CAPABILITY__ | \
     __CHERI_CAP_PERMISSION_LOAD_MUTABLE__ | \
     KERNEL_LEVEL_PERMS)

    .section .text.boot, "ax", @progbits
    .align 4
    .globl _start
_start:
    /*
     * Step 0: Per-hart M-mode setup (-bios none).
     *
     * At reset, QEMU starts every hart in M-mode at 0x80000000 in integer
     * pointer mode with `mseccfg.CRE = 0` and:
     *   a0 = hart ID
     *   a1 = physical address of the Flattened Device Tree (DTB)
     *
     * Every hart (< MAX_HARTS = 16) configures its M-mode CSRs and carries on
     * to step 2, still in M-mode. Nothing runs below M-mode, so nothing is set
     * up for lower modes: no counter enables (`mcounteren`), no CHERI enable
     * in `menvcfg`, and no PMP entries (with none, PMP does not constrain
     * M-mode).
     */
    csrsi   0x747, 8            /* mseccfg.CRE = 1 (enable CHERI in M-mode) */
    .word   0x12001033          /* modesw.cap */
    li      t0, 16              /* platform::MAX_HARTS */
    bgeu    a0, t0, _hang

    /* Delegate nothing: every exception and interrupt is taken in M-mode, at
     * `mtvecc`. */
    csrw    mideleg, zero
    csrw    medeleg, zero

    /* Clear interrupt/paging state and enable only the machine software
     * interrupt (mie.MSIE, bit 3), so a CLINT `msip` poke wakes a hart from
     * `wfi`. Addresses stay physical until the MMU is turned on (`vm::init`,
     * `.Lsecondary_start`): `satp` is Bare and `mmodemmu` (CSR 0x7c0) resets
     * to 0. */
    csrw    mip, zero
    li      t0, (1 << 3)
    csrw    mie, t0
    csrw    satp, zero

    /* mstatus: MIE = 0 (interrupts masked), MPP = M (bits 11-12, the mode an
     * `mret` returns to), FS = Initial (bit 13, FPU on). */
    li      t0, (3 << 11) | (1 << 13)
    csrw    mstatus, t0

    /* Until step 8 installs the trap vector, a trap parks the hart in
     * `_hang`. */
    auipcc  ct0, 0
    llc     ct1, _hang
    scaddr  ct0, ct0, t1
    csrw    mtvecc, ct0

    /*
     * Step 2: Derive master root data capability (cs11) and bounded kernel
     * code capability (cs10) from initial PCC.
     *
     * cs10 is restricted strictly to [_kernel_start, _got_end) (covering only
     * .text, .rodata, __cap_relocs, and .got — excluding writable
     * .data/.bss.stack/.bss) with KERNEL_CODE_PERMS (stripping Store, Seal,
     * and Unseal). All kernel function pointers, mtvecc, and kernel_main's PCC
     * are derived from cs10 so the kernel never executes with an unbounded PCC.
     */
    auipcc  cs11, 0
    scaddr  cs11, cs11, zero    /* cs11 = Root Data Capability (spanning 64-bit address space) */

    auipcc  cs10, 0
    llc     ct0, _kernel_start
    llc     ct1, _got_end
    sub     t1, t1, t0          /* t1 = _got_end - _kernel_start */
    scaddr  cs10, cs10, t0
    scbndsr cs10, cs10, t1      /* Bound cs10 to [_kernel_start, _got_end) */
    li      t1, KERNEL_CODE_PERMS
    acperm  cs10, cs10, t1      /* Strip Store, Seal, Unseal */

    /*
     * Step 3: Capture Hart ID (a0) and DTB capability (a1), then elect the
     * boot hart atomically via `_boot_lottery` so no hart ID is hardcoded.
     * Secondary harts wait in `.Lsecondary_wait_loop` until the boot hart
     * discovers all DTB harts and provisions their stacks and page tables.
     */
    cmv     cs0, ca0            /* cs0 = Hart ID */
    scaddr  cs2, cs11, a1       /* cs2 = DTB capability derived from root at address in a1 */
    li      t1, 0x01000000      /* 16 MiB max FDT bound */
    scbndsr cs2, cs2, t1
    li      t1, __CHERI_CAP_PERMISSION_READ__
    acperm  cs2, cs2, t1

    llc     ct0, _boot_lottery
    scaddr  ct0, cs11, t0
    li      t1, 1
    amoswap.w.aq t1, t1, (ct0)
    bnez    t1, .Lsecondary_wait_loop

    /*
     * Step 4: Set up tightly-bounded, non-executable stacks (csp and mscratchc)
     * derived from cs11, masked to KERNEL_DATA_PERMS (stripping Execute, Seal,
     * Unseal, and AccessSystemRegs).
     */
    li      t2, KERNEL_DATA_PERMS
    llc     ct0, _kernel_stack_base
    scaddr  csp, cs11, t0
    li      t1, 65536
    scbndsr csp, csp, t1        /* Set stack capability bounds to exactly 64KB */
    acperm  csp, csp, t2        /* Strip Execute, Seal, Unseal, AccessSystemRegs */
    cadd    csp, csp, t1        /* Set SP to top of stack (stack grows downward) */

    llc     ct0, _boot_ksp_base
    scaddr  ct0, cs11, t0
    li      t1, 16384
    scbndsr ct0, ct0, t1
    acperm  ct0, ct0, t2        /* Strip Execute, Seal, Unseal, AccessSystemRegs */
    cadd    ct0, ct0, t1
    csrw    mscratchc, ct0      /* Initialize per-hart kernel SP in mscratchc */

    /*
     * Step 5: Set up Capability Global Pointer (cgp), tightly bounded to
     * [_got_start, _got_end) and masked to KERNEL_RO_TABLE_PERMS (.got is
     * never written after Step 6 completes).
     */
    llc     ct0, _got_start
    llc     ct1, _got_end
    sub     t1, t1, t0
    scaddr  cgp, cs11, t0
    scbndsr cgp, cgp, t1
    li      t1, KERNEL_RO_TABLE_PERMS
    acperm  cgp, cgp, t1

    /* Step 6: Process __cap_relocs table */
    llc     ca4, ___cap_relocs_start
    scaddr  ca4, cs11, a4
    llc     ca5, ___cap_relocs_end
    scaddr  ca5, cs11, a5
    bgeu    a4, a5, .Lrelocs_done

.Lreloc_loop:
    ld      t0, 0(ca4)          /* t0 = capability location in memory (in .got / .data) */
    scaddr  ct3, cs11, t0       /* ct3 = writable pointer to target capability slot */
    
    ld      t1, 8(ca4)          /* t1 = target object base address */
    beqz    t1, .Lreloc_null

    /* Check if function pointer (flag bit 63 set) */
    ld      t4, 32(ca4)         /* t4 = flags */
    bgez    t4, .Lreloc_data

    /* Function pointer: derive from bounded cs10 (KERNEL_CODE_PERMS) */
    scaddr  ct5, cs10, t1
    j       .Lreloc_store

.Lreloc_data:
    /*
     * Data or read-only object: derive from cs11 and strip Execute, Seal,
     * Unseal, and AccessSystemRegs. If __cap_relocs flag bit 62 (CONSTANT_REL)
     * is set, also strip Store and LoadMutable so .rodata capabilities in .got
     * are hardware read-only.
     */
    scaddr  ct5, cs11, t1
    slli    t2, t4, 1           /* Shift bit 62 (CONSTANT_REL) into sign bit 63 */
    bltz    t2, .Lreloc_rodata
    li      t2, KERNEL_DATA_PERMS
    acperm  ct5, ct5, t2
    j       .Lreloc_store

.Lreloc_rodata:
    li      t2, KERNEL_RODATA_PERMS
    acperm  ct5, ct5, t2

.Lreloc_store:
    /* Bound the capability to the object it names. The size is field 3 of the
       record, at +24, and is set for every entry the linker emits. scaddr only
       changed the address, so without this the capability keeps the bounds of
       the root it was derived from, which span the whole address space.

       Bounds are applied to the base, before the offset is added, because the
       size is relative to the base. t6 is used because t3 and t5 are the
       integer halves of ct3 and ct5, both of which are live here. */
    ld      t6, 24(ca4)         /* t6 = object size in bytes */
    beqz    t6, .Lreloc_null    /* Refuse size-0 relocations so no unbounded cap enters .got */
    scbndsr ct5, ct5, t6        /* bounds = [base, base+size), rounded out */

    /* Add offset within target object */
    ld      t2, 16(ca4)         /* t2 = offset */
    cadd    ct5, ct5, t2

    /* Store valid CHERI capability fat pointer to destination slot */
    csc     ct5, 0(ct3)
    j       .Lnext_reloc

.Lreloc_null:
    csc     cnull, 0(ct3)

.Lnext_reloc:
    caddi   ca4, ca4, 40        /* Each __cap_relocs record is 40 bytes */
    bltu    a4, a5, .Lreloc_loop

.Lrelocs_done:
    fence   rw, rw
    fence.i

    /* Step 7: Zero BSS using cs11 (Root Data Capability) */
    llc     ca4, _bss_start
    scaddr  ca4, cs11, a4
    llc     ca5, _bss_end
    scaddr  ca5, cs11, a5
    bgeu    a4, a5, .Lbss_done

.Lbss_loop:
    csc     cnull, 0(ca4)
    caddi   ca4, ca4, 16        /* 16 bytes (128-bit capability width) per iteration */
    bltu    a4, a5, .Lbss_loop

.Lbss_done:
    fence   rw, rw
    fence.i

    /*
     * Step 8: Set up the trap vector (mtvecc) derived from bounded cs10 so trap
     * handlers execute with PCC bounded to [_kernel_start, _got_end).
     */
    llc     ct0, _early_trap_entry
    scaddr  ct0, cs10, t0
    csrw    mtvecc, ct0

    /*
     * Step 9: Call kernel_main(root_data_cap in ca0, hartid in ca1, dtb_cap in ca2).
     * Derive kernel_main entry from bounded cs10 so the kernel executes with a
     * bounded PCC, and scrub all temporary boot capability registers first.
     */
    cmv     ca0, cs11
    cmv     ca1, cs0
    cmv     ca2, cs2
    llc     ct0, kernel_main
    scaddr  ct0, cs10, t0
    cmv     cs0, cnull
    cmv     cs2, cnull
    cmv     cs10, cnull
    cmv     cs11, cnull
    cmv     ca4, cnull
    cmv     ca5, cnull
    cmv     ct3, cnull
    cmv     ct5, cnull
    cjalr   cra, ct0
    j       _hang

.Lsecondary_wait_loop:
    /* Point cs1 (callee-saved) at this hart's 64-byte slot in `_hart_boot_table`,
     * tightly bounded to 64 bytes with `KERNEL_DATA_PERMS`. */
    llc     ct0, _hart_boot_table
    scaddr  cs1, cs11, t0
    slli    t0, s0, 6           /* hartid * 64 */
    cadd    cs1, cs1, t0
    li      t0, 64
    scbndsr cs1, cs1, t0
    li      t0, KERNEL_DATA_PERMS
    acperm  cs1, cs1, t0

.Lsecondary_spin:
    ld      t0, 40(cs1)         /* state: 0 = waiting, 1 = go */
    bnez    t0, .Lsecondary_start
    wfi
    j       .Lsecondary_spin

.Lsecondary_start:
    /* The poke that ended the wait above stays pending (`msip` is still set)
     * until `irq::init_hart` clears it, inside `secondary_hart_init`. */
    fence   r, r

    /* Load bounded 64 KiB host stack (csp) and scrub handoff slot */
    clc     csp, 0(cs1)
    csc     cnull, 0(cs1)

    /* Load bounded 16 KiB kernel entry stack (mscratchc) and scrub handoff slot */
    clc     ct0, 16(cs1)
    csc     cnull, 16(cs1)
    csrw    mscratchc, ct0

    /* Enable mstatus.SUM | mstatus.MXR, load the boot hart's Sv39 satp, and
     * set mmodemmu.ENABLE (CSR 0x7c0, bit 0): from the next instruction this
     * hart's M-mode accesses go through the MMU. This code, the boot table and
     * the stacks are all in the identity-mapped kernel region. */
    li      t0, (1 << 18) | (1 << 19)
    csrs    mstatus, t0
    ld      t0, 32(cs1)
    sd      zero, 32(cs1)
    csrw    satp, t0
    sfence.vma zero, zero
    csrsi   0x7c0, 1

    /* Set up bounded cgp ([_got_start, _got_end), KERNEL_RO_TABLE_PERMS) */
    llc     ct0, _got_start
    llc     ct1, _got_end
    sub     t1, t1, t0
    scaddr  cgp, cs11, t0
    scbndsr cgp, cgp, t1
    li      t1, KERNEL_RO_TABLE_PERMS
    acperm  cgp, cgp, t1

    /* Set up bounded mtvecc (_early_trap_entry derived from cs10) */
    llc     ct0, _early_trap_entry
    scaddr  ct0, cs10, t0
    csrw    mtvecc, ct0

    /* Call secondary_hart_init(hartid in ca0) with bounded PCC (cs10),
     * scrubbing all temporary capability registers except callee-saved cs1. */
    cmv     ca0, cs0
    llc     ct0, secondary_hart_init
    scaddr  ct0, cs10, t0
    cmv     cs0, cnull
    cmv     cs2, cnull
    cmv     cs10, cnull
    cmv     cs11, cnull
    cmv     ct1, cnull
    cjalr   cra, ct0

    /* Keep this hart's CLINT `msip` in cs2 for the idle loop and scrub its
     * slot, signal boot hart that this hart is online (state = 2), scrub
     * cs1/cra/ct0, and park. */
    clc     cs2, 48(cs1)
    csc     cnull, 48(cs1)
    fence   rw, w
    li      t0, 2
    sd      t0, 40(cs1)
    cmv     cs1, cnull
    cmv     cra, cnull
    cmv     ct0, cnull
.Lsecondary_idle:
    /* Parked with interrupts masked (DESIGN.md §4.4). A poke ends the `wfi`;
     * clearing it is all this hart does with it, so the next `wfi` sleeps. */
    wfi
    sw      zero, 0(cs2)        /* msip[this hart] = 0 */
    j       .Lsecondary_idle

    .align 2                    /* `mtvecc` until step 8: 4-byte aligned */
_hang:
    wfi
    j       _hang
