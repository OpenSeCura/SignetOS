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

#include <stdint.h>
#include <signetos/types.hpp>

namespace signetos::uart {

// Initializes the UART 16550 console using a strictly bounded MMIO capability
void init(Capability root_data_cap);

// Each of the printing calls below holds the console lock for the whole call,
// so two harts' output interleaves by call, not by character. Kernel code
// only: a compartment that prints drives the device itself through a window
// user space carves from the MMIO capability in the boot manifest.

// Outputs a single character to the serial console
void putchar(char ch);

// Outputs a null-terminated string to the serial console
void print(const char* str);

// Outputs a 64-bit value in hexadecimal format (16 hex digits)
void print_hex64(uint64_t val);

// Outputs a 64-bit unsigned integer in decimal format
void print_dec(uint64_t val);

// Inspects and prints CHERI capability metadata (tag, perms, base, length,
// address, and whether it is sealed and if so with which object type). Used
// by the kernel's panic reports.
void print_cap(const char* label, Capability cap);

// The kernel is stopping. From here on the printing calls do not wait for the
// console lock: the hart that is stopping may be the one holding it (a fault
// inside a print), and what it has to say must not be lost to a wait. Called
// by `panic`, `qemu_poweroff` and `trap::trap_report` before they print.
void halting();

// Signals QEMU to terminate cleanly via the virt test device at 0x100000
[[noreturn]] void qemu_poweroff(int exit_code);

// Prints `[PANIC] msg` and powers off. For boot-time invariants that, if
// broken, leave the kernel unable to mint any handle at all.
[[noreturn]] void panic(const char* msg);

} // namespace signetos::uart
