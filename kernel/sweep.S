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
 * sweep.S - The parts of a revocation sweep that cannot be C++
 *
 * A sweep (revoke.hpp) gives every page of the pool a generation and checks
 * a page before the first capability is loaded from it (vm.hpp, CHECKED
 * PAGES). The kernel is no part of that: it never takes the fault, and what
 * it sweeps with is never swept. Three places need assembly to keep that
 * true, and a fourth for an instruction C++ has no name for.
 *
 *   1. `__signetos_new_generation`: the step from one generation to the
 *      next. The hart's generation and the page table entries of the
 *      kernel's own mappings have to change together: in between, any
 *      capability the kernel loaded from memory would trap. So everything
 *      here is held in registers, and the only memory read is integers.
 *
 *   2. `__signetos_check_on`: runs a check of pages on the hart's own stack
 *      rather than on the thread's, so that the check costs the thread's
 *      kernel stack a few bytes however deep it goes (asm_macros.h,
 *      KERNEL-STACK ROOM), and runs on memory that is never stale.
 *
 *   3. `__signetos_stop_here`: where every other hart waits while one hart
 *      takes that step (smp.hpp, THE STOP), and follows it. The kernel's
 *      mappings change generation under a stopped hart before the hart
 *      itself does, so from the moment it says it has stopped until it has
 *      followed it loads no capability either.
 *
 *   4. `__signetos_clear_tag_if`: clears the tag of a capability in memory
 *      only if it is still the capability that was looked at, so that a
 *      check of a page never undoes what another hart stored there
 *      meanwhile.
 *
 * All are called with interrupts masked, as all kernel code runs.
 */

#include <signetos/asm_macros.h>

    .section .text, "ax", @progbits
    .option capmode
    .option norvc

/* =========================================================================
 * 1. `__signetos_new_generation`
 * =========================================================================
 * Inputs:
 *   ca0 = a capability spanning the direct map (vm.cpp, `s_direct`)
 *   ca1 = `a2` pairs of words, one pair per run of page table entries: the
 *         address of the run's first entry in the direct map, and how many
 *         entries it has
 *   a2  = the number of runs
 *   a3  = the bit to flip in every valid entry of every run (pte::CapGen)
 *
 * Flips the bit in each entry, then the hart's generation (`mstatus.UCRG`),
 * then drops every cached translation. Entries that are not valid are left
 * alone (the unused part of a table). A leaf: it uses no stack, and returns
 * through `cra`.
 */

    .align 4
    .globl __signetos_new_generation
    .type __signetos_new_generation, @function
__signetos_new_generation:
.Lnext_run:
    beqz    a2, .Lflip_hart
    ld      t0, 0(ca1)                  /* where the run starts */
    ld      t1, 8(ca1)                  /* how many entries */
    scaddr  ct2, ca0, t0                /* ct2 = the entry, through the direct map */
.Lnext_entry:
    beqz    t1, .Lrun_done
    ld      t3, 0(ct2)
    andi    t4, t3, 1                   /* pte::Valid */
    beqz    t4, .Lentry_done
    xor     t3, t3, a3
    sd      t3, 0(ct2)
.Lentry_done:
    caddi   ct2, ct2, 8
    addi    t1, t1, -1
    j       .Lnext_entry
.Lrun_done:
    caddi   ca1, ca1, 16
    addi    a2, a2, -1
    j       .Lnext_run

.Lflip_hart:
    /* The hart follows its entries. From the first `sd` above to here no
     * capability has been loaded from memory. */
    li      t0, MSTATUS_UCRG
    csrr    t1, mstatus
    xor     t1, t1, t0
    csrw    mstatus, t1
    sfence.vma zero, zero
    cmv     ct2, cnull                  /* nothing keeps the direct map */
    cmv     ca0, cnull
    ret
    .size __signetos_new_generation, . - __signetos_new_generation


/* =========================================================================
 * 2. `__signetos_check_on`
 * =========================================================================
 * Inputs:
 *   ca0 = the top of the stack to run on (thread.hpp, `spare_stack`)
 *   a1  = `va`
 *   a2  = `len`
 *
 * Calls `__signetos_check_pages(va, len)` (revoke.cpp) on that stack and
 * comes back to the caller's. The caller's stack keeps two capabilities
 * meanwhile; it is one the kernel is running on, so it is checked already
 * and the loads back from it cannot trap.
 */

    .align 4
    .globl __signetos_check_on
    .type __signetos_check_on, @function
__signetos_check_on:
    caddi   csp, csp, -32
    csc     cra, 0(csp)
    csc     cs0, 16(csp)
    cmv     cs0, csp                    /* cs0 = the caller's stack */
    cmv     csp, ca0
    mv      a0, a1
    mv      a1, a2
    cjal    cra, __signetos_check_pages
    cmv     csp, cs0
    clc     cra, 0(csp)
    clc     cs0, 16(csp)
    caddi   csp, csp, 32
    ret
    .size __signetos_check_on, . - __signetos_check_on


/* =========================================================================
 * 3. `__signetos_stop_here`
 * =========================================================================
 * Inputs:
 *   ca0 = `smp::Stop` (smp.cpp; words at the STOP_* offsets of asm_macros.h)
 *   ca1 = this hart's CLINT `msip`
 *   ca2 = the `msip` of the hart that asked for the stop
 *
 * Says that this hart has stopped, sleeps until the hart that asked lets
 * everyone go, then takes the generation it left in the Stop
 * (`mstatus.UCRG`), drops every cached translation and says that it has gone
 * on. Each thing it says is a count going up and then a poke, so the other
 * hart can sleep too; and it clears its own poke before it looks at the
 * phase, so one sent after that look ends the `wfi` instead of being lost.
 *
 * Between the first count and the new `mstatus` the only memory read is the
 * phase and the generation: integers, through a capability held in a
 * register. A leaf: it uses no stack, and returns through `cra`. Only a poke
 * ends its `wfi`: `mie` is narrowed to that for as long as it waits.
 */

    .align 4
    .globl __signetos_stop_here
    .type __signetos_stop_here, @function
__signetos_stop_here:
    csrr    t5, mie
    li      t0, MIE_MSIE
    csrw    mie, t0
    caddi   ct3, ca0, STOP_STOPPED
    li      t0, 1
    amoadd.d zero, t0, (ct3)            /* stopped += 1 */
    fence   w, o
    sw      t0, 0(ca2)                  /* and the hart that asked is told */
.Lstop_wait:
    sw      zero, 0(ca1)                /* the poke that got us here is taken */
    fence   o, r
    ld      t1, STOP_PHASE(ca0)
    li      t2, STOP_PHASE_STOP
    bne     t1, t2, .Lstop_over
    wfi
    j       .Lstop_wait
.Lstop_over:
    ld      t1, STOP_UCRG(ca0)          /* MSTATUS_UCRG or 0 */
    li      t2, MSTATUS_UCRG
    csrr    t3, mstatus
    or      t3, t3, t2
    xor     t3, t3, t2
    or      t3, t3, t1
    csrw    mstatus, t3                 /* this hart follows */
    sfence.vma zero, zero
    caddi   ct3, ca0, STOP_RESUMED
    li      t0, 1
    amoadd.d zero, t0, (ct3)            /* resumed += 1 */
    fence   w, o
    sw      t0, 0(ca2)
    csrw    mie, t5
    cmv     ct3, cnull
    cmv     ca0, cnull
    cmv     ca1, cnull
    cmv     ca2, cnull
    ret
    .size __signetos_stop_here, . - __signetos_stop_here


/* =========================================================================
 * 4. `__signetos_clear_tag_if`
 * =========================================================================
 * Inputs:
 *   ca0 = where a capability is kept
 *   ca1 = the capability that was read from there
 *   ca2 = the same without its tag
 *
 * Stores `ca2` there if what is there is still exactly `ca1` -- every bit
 * and the tag, not just the address -- in one step as far as any other hart
 * can tell. Returns 1 if it did, 0 if something else is there now.
 */

    .align 4
    .globl __signetos_clear_tag_if
    .type __signetos_clear_tag_if, @function
__signetos_clear_tag_if:
.Lclear_again:
    lr.c    ct0, (ca0)
    sceq    t1, ct0, ca1
    beqz    t1, .Lclear_changed
    sc.c    t1, ca2, (ca0)
    bnez    t1, .Lclear_again
    cmv     ct0, cnull
    li      a0, 1
    ret
.Lclear_changed:
    cmv     ct0, cnull
    li      a0, 0
    ret
    .size __signetos_clear_tag_if, . - __signetos_clear_tag_if
