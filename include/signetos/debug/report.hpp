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
// report.hpp - The kernel's diagnostics: everything it says on the console
//
// The core kernel (kernel/*.cpp) does not print. When it has something to
// say -- an invariant broke, a fault was unwound, a thread is being ended --
// it calls one of these, and kernel/debug/report.cpp turns that into text on
// the console (hw/uart.hpp). The core decides what happens; this only
// describes it.
//

#include <stdint.h>

#include <signetos/types.hpp>

namespace signetos::debug {

// --- Halting ----------------------------------------------------------------

// A kernel invariant does not hold: prints `msg` and powers the machine off
// with a non-zero exit code.
[[noreturn]] void panic(const char* msg);

// A synchronous exception the kernel cannot hand to anyone (`why`: raised by
// kernel code, in host context, ...): prints the cause, decoded, and the
// trap registers, then powers off. `sp` is the stack pointer at the fault,
// for orientation.
[[noreturn]] void trap_report(const char* why, uint64_t mcause, uint64_t mepc,
                              uint64_t mtval, uint64_t mtval2, uint64_t sp);

// --- Events -----------------------------------------------------------------

// A fault in compartment `comp_uid` that no handler of the compartment's
// took (`why`); the trap path unwinds it.
void fault_report(const char* why, uint64_t comp_uid, uint64_t mcause,
                  uint64_t mepc, uint64_t mtval, uint64_t mtval2);

// The running thread is being ended by `who` ("unwind", "trap") because
// `why`.
void thread_ending(const char* who, const char* why);

// `online` of `total` harts are up, booted from `boot_hart`.
void harts_online(uint64_t online, uint64_t total, uint64_t boot_hart);

// One of the capabilities the kernel hands to `init` at boot.
void boot_capability(const char* label, Capability cap);

// A successful thread switch from `prev_tid` (0: host context) to `tid`.
// Printed only in a TRACE_SWITCH=1 build; otherwise compiled away.
#ifdef SIGNETOS_TRACE_SWITCH
void trace_switch(uint64_t prev_tid, uint64_t tid);
#else
inline void trace_switch(uint64_t, uint64_t) {}
#endif

// --- Self-tests -------------------------------------------------------------

// Exercises the quota tree against a scratch subtree of `root` and panics on
// the first failed check (kernel/debug/quota_selftest.cpp). Run at boot in a
// QUOTA_SELFTEST=1 build.
void quota_self_test(Capability root);

}  // namespace signetos::debug
