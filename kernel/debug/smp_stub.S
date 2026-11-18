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
 * smp_stub.S - The thread the SMP self-test runs on a second hart
 *
 * Kernel text run as a compartment's code (`sentry::create_kernel`): its PCC
 * is this stub alone, without AccessSystemRegs, so to the kernel it is
 * compartment code like any other. It is entered with `ca0` = the box, a
 * page of its compartment that smp_selftest.cpp shares with it: three
 * capabilities, then words the thread reports in. The offsets are
 * smp_selftest.cpp's.
 */

#define BOX_VICTIM      0       /* a capability to memory that will be freed */
#define BOX_SELF        16      /* a capability to the box: never freed */
#define BOX_COPY        32      /* where the thread stores BOX_SELF again */
#define BOX_STATE       64      /* 1 holding, 2 register cleared, 3 reported */
#define BOX_IN_PAGE     72      /* 1 + the tag of BOX_VICTIM loaded again */
#define BOX_KEPT        80      /* 1 + the tag of BOX_SELF loaded then */
#define BOX_ROUNDS      88      /* pokes survived since, one per sweep */
#define BOX_LOST        96      /* 1 if BOX_SELF ever came back untagged */

    .section .text, "ax", @progbits
    .option capmode
    .option norvc

    .align 4
    .globl __smp_test_thread
    .globl __smp_test_thread_end
    .type __smp_test_thread, @function
__smp_test_thread:
    /* The capability, in a register, and say so. */
    clc     cs1, BOX_VICTIM(ca0)
    li      t0, 1
    sd      t0, BOX_STATE(ca0)

    /* Until the register loses its tag. Nothing here loads or stores, so no
     * page is checked on this thread's account: only the start of a sweep,
     * which stops this hart and checks the registers the trap saved, can end
     * the loop. */
1:  gctag   t0, cs1
    bnez    t0, 1b
    li      t0, 2
    sd      t0, BOX_STATE(ca0)

    /* The copy in the box. The page is stale now, so this load traps and
     * the page is checked on this hart; what comes back has no tag. A
     * capability to memory that was not freed keeps its. */
    clc     cs2, BOX_VICTIM(ca0)
    gctag   t0, cs2
    addi    t0, t0, 1
    sd      t0, BOX_IN_PAGE(ca0)
    clc     cs2, BOX_SELF(ca0)
    gctag   t0, cs2
    addi    t0, t0, 1
    sd      t0, BOX_KEPT(ca0)
    li      t0, 3
    sd      t0, BOX_STATE(ca0)

    /* For as long as the machine runs: asleep, interruptible, and woken by
     * the poke that starts each sweep. Each time, a capability is loaded
     * from the box (stale again) and stored back. */
2:  wfi
    clc     cs2, BOX_SELF(ca0)
    gctag   t0, cs2
    beqz    t0, 3f
    csc     cs2, BOX_COPY(ca0)
    ld      t1, BOX_ROUNDS(ca0)
    addi    t1, t1, 1
    sd      t1, BOX_ROUNDS(ca0)
    j       2b
3:  li      t0, 1
    sd      t0, BOX_LOST(ca0)
    j       2b
__smp_test_thread_end:
    .size __smp_test_thread, . - __smp_test_thread
