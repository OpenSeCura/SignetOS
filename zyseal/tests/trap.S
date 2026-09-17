/*
 * Copyright 2026 Google LLC (Cherified Team)
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
 * trap.S - minimal resuming trap handler for the Zyseal audit.
 *
 * On a synchronous exception: record that it happened, record scause, skip the
 * faulting instruction, and resume. That lets the C code probe whether a given
 * operation faults without dying.
 *
 * cs9 (x25) is reserved by the build (-ffixed-x25) and holds a capability to
 * g_trap_state[2]:
 *     [0] = trapped flag
 *     [8] = scause
 *
 * ct0 is stashed in sscratchc so the handler has a working register without
 * disturbing the interrupted code.
 *
 * Skipping by 4 is only correct for uncompressed instructions, which is why
 * every probe in zaudit.c wraps its faulting instruction in .option norvc.
 */
    .section .text.trap, "ax", @progbits
    .align 4
    .globl _trap_entry
    .option capmode
    .option norvc

_trap_entry:
    csrw    sscratchc, ct0          /* stash ct0 */

    csrr    t0, scause
    bltz    t0, .Lasync             /* bit 63 set => interrupt, not our business */

    /* g_trap_state[0] = 1 */
    li      t0, 1
    sd      t0, 0(cs9)
    /* g_trap_state[1] = scause */
    csrr    t0, scause
    sd      t0, 8(cs9)

    /* Resume at the next instruction. */
    csrr    ct0, sepcc
    caddi   ct0, ct0, 4
    csrw    sepcc, ct0

    csrr    ct0, sscratchc
    sret

.Lasync:
    csrw    sie, zero               /* shouldn't happen; silence and resume */
    csrr    ct0, sscratchc
    sret
