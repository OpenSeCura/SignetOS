#!/bin/bash

# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# run_signetos_terminal.sh - Builds and launches SignetOS pure-capability CHERI RISC-V microkernel
# in QEMU interactive terminal CLI mode.
#
# The toolchain location comes from the Makefile: CHERI_ROOT (default ~/cheri,
# as for zyseal/setup.sh), or CHERI_SDK_BIN / QEMU individually, from the
# environment.
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=================================================================================="
echo " Building SignetOS v1.0 (Pure-Capability CHERI RISC-V -mabi=l64pc128d ABI)..."
echo "=================================================================================="
make -C "$ROOT_DIR" clean
make -C "$ROOT_DIR" signetos.elf disk.img

echo "=================================================================================="
echo " Launching SignetOS on QEMU CHERI RISC-V..."
echo " - Press Ctrl+A then X to force terminate QEMU at any time."
echo " - Or type 'shutdown' at the SignetOS> prompt ('help' lists commands)."
echo " - Console input is interrupt driven (UART -> PLIC -> trap_mgr -> uart -> shell);"
echo "   the shell sleeps in sched.block between keystrokes."
echo " - TRACE_SWITCH=1 $0 logs every thread switch the scheduler makes."
echo "=================================================================================="
# The QEMU command line (CPU flags, virtio-blk disk, serial console) lives in
# the Makefile's `term` target. Zyseal=on there is required, not optional: the
# kernel executes YSEAL/YUNSEAL during boot, and on a plain rv64 those are
# illegal instructions, so the symptom is a silent hang right after the banner.
exec make -s -C "$ROOT_DIR" term
