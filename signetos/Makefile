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

# ---------------------------------------------------------------------------
# Toolchain.
#
# The SDK and QEMU below carry the Zyseal extension: the YSEAL/YUNSEAL
# instructions, the SE/US permissions, and a 4-bit CT field. Zyseal is a local
# non-ratified dialect; ../zyseal/setup.sh fetches, patches and builds the
# toolchain (see README.md).
#
# Zyseal is mandatory. The kernel's object model is hardware sealing and there
# is no software fallback.
#
# Zylevels1=on enables CHERI capability levels (the GL flag plus the LG/SL
# permissions). QEMU's `rv64` model has it off by default
# and only then advertises `zcherilevels` in the device tree. The kernel keeps
# the three bits on every derivation (`perms::Levels`, `KERNEL_LEVEL_PERMS`) so
# it boots either way; nothing relabels capabilities as local yet. MARCH stays
# without `_zcherilevels` on purpose: the flag changes no code generation, only
# whether the toolchain defines the level macros, and both headers fall back
# to the fixed ISA bit positions.
#
# CHERI_ROOT is the install root ../zyseal/setup.sh used (its default is
# ~/cheri); the patched tools are under $(CHERI_ROOT)/zyseal. Override it (or
# CHERI_SDK_BIN / QEMU individually) on the command line or in the environment
# to use a toolchain somewhere else.
# ---------------------------------------------------------------------------
CHERI_ROOT    ?= $(HOME)/cheri
CHERI_SDK_BIN ?= $(CHERI_ROOT)/zyseal/llvm-build/bin
QEMU          ?= $(CHERI_ROOT)/zyseal/qemu-build/qemu-system-riscv64cheristd
MARCH         = rv64gc_zcheripurecap_zyseal
QEMU_CPU      = rv64,Zyseal=on,Zylevels1=on
EXTRA_LDFLAGS =

CXX     = $(CHERI_SDK_BIN)/clang++
CC      = $(CHERI_SDK_BIN)/clang
AS      = $(CHERI_SDK_BIN)/clang
LD      = $(CHERI_SDK_BIN)/ld.lld
OBJCOPY = $(CHERI_SDK_BIN)/llvm-objcopy
OBJDUMP = $(CHERI_SDK_BIN)/llvm-objdump

ifeq ($(filter clean,$(MAKECMDGOALS)),)
ifeq ($(wildcard $(CXX)),)
$(error CHERI clang not found at $(CXX). Build the toolchain with \
../zyseal/setup.sh, or set CHERI_ROOT / CHERI_SDK_BIN)
endif
endif

OPT ?= -O2

# TRACE_SWITCH=1 makes the kernel print one line on the UART for every
# successful `sys_thread_switch` (`kernel/thread.cpp`, `__signetos_thread_dispatch`).
# Every switch the scheduler compartment makes -- dispatcher, yield and the
# timer tick -- goes through it, so it sees them all. Off by default.
TRACE_SWITCH ?= 0
ifeq ($(TRACE_SWITCH),1)
TRACE_DEFS = -DSIGNETOS_TRACE_SWITCH
else
TRACE_DEFS =
endif

CXXFLAGS = -target riscv64-unknown-freebsd -march=$(MARCH) -mabi=l64pc128d \
           -std=c++20 -ffreestanding -nostdlib -nostdinc++ -nostdinc -U__FreeBSD__ \
           -fno-exceptions -fno-rtti -fno-unwind-tables -fno-asynchronous-unwind-tables \
           -fno-threadsafe-statics -fno-use-cxa-atexit -fno-common -fno-jump-tables \
           -mcmodel=medany $(OPT) -Wall -Wextra \
           -Wno-cheri-capability-misuse -Wno-cheri-implicit-conversion -Wno-cheri-pointer-conversion \
           -Iinclude -Iinclude/libc -g $(TRACE_DEFS)

ASFLAGS  = -target riscv64-unknown-freebsd -march=$(MARCH) -mabi=l64pc128d \
           -mcmodel=medany -ffreestanding -nostdlib -nostdinc -U__FreeBSD__ \
           -Iinclude -Iinclude/libc -g

LDFLAGS      = -fuse-ld=lld -T kernel/linker.ld -nostdlib -static -Wl,--local-caprelocs=legacy $(EXTRA_LDFLAGS)
USER_LDFLAGS = -fuse-ld=lld -T user/compartment.ld -nostdlib -static -Wl,--local-caprelocs=legacy

# Standalone user-space compartments, compiled and linked separately into
# flat binaries using the shared runtime in `user/`.
#
# `boot/` (`BOOT_COMPS`): embedded into the kernel via `kernel/boot_images.S`
# -- `init` and what it needs to reach the disk (`uart`, `blk`, `loader`, `fs`).
#
# `external/` (`EXT_SERVICES` and `EXT_APPS`): written into `disk.img` at build
# time by `tools/signetfs.py` (never linked into the kernel image).
#   - `external/services/`: root-owned system services (`naming`, `sched`,
#     `trap_mgr`, `shell`) that `init` reads from `fs` out of `/` and loads
#     via `loader`.
#   - `external/apps/`: programs, written to `/bin`, which the shell reaches
#     through a read-only disk quota rooted there and can `run`.
BOOT_COMPS = init loader fs uart blk
BOOT_SRCS  = $(patsubst %,boot/%.cpp,$(BOOT_COMPS))
BOOT_OBJS  = $(patsubst %.cpp,%.o,$(BOOT_SRCS))
BOOT_ELFS  = $(patsubst %,boot/%.elf,$(BOOT_COMPS))
BOOT_BINS  = $(patsubst %,boot/%.bin,$(BOOT_COMPS))

EXT_SERVICES     = naming sched trap_mgr shell
EXT_SERVICE_SRCS = $(patsubst %,external/services/%.cpp,$(EXT_SERVICES))
EXT_SERVICE_OBJS = $(patsubst %.cpp,%.o,$(EXT_SERVICE_SRCS))
EXT_SERVICE_ELFS = $(patsubst %,external/services/%.elf,$(EXT_SERVICES))
EXT_SERVICE_BINS = $(patsubst %,external/services/%.bin,$(EXT_SERVICES))

EXT_APPS     = hello logo
EXT_APP_SRCS = $(patsubst %,external/apps/%.cpp,$(EXT_APPS))
EXT_APP_OBJS = $(patsubst %.cpp,%.o,$(EXT_APP_SRCS))
EXT_APP_ELFS = $(patsubst %,external/apps/%.elf,$(EXT_APPS))
EXT_APP_BINS = $(patsubst %,external/apps/%.bin,$(EXT_APPS))

COMP_OBJS = user/entry.o $(BOOT_OBJS) $(EXT_SERVICE_OBJS) $(EXT_APP_OBJS)
COMP_ELFS = $(BOOT_ELFS) $(EXT_SERVICE_ELFS) $(EXT_APP_ELFS)
COMP_BINS = $(BOOT_BINS) $(EXT_SERVICE_BINS) $(EXT_APP_BINS)

# Raw disk image behind the virtio-blk device the `blk` driver talks to,
# carrying the `external/` images. `tools/signetfs.py put` formats it when it
# is missing or blank and otherwise replaces just those files, so whatever the
# system wrote on earlier boots survives a rebuild; delete it to start fresh.
DISK_IMG   = disk.img
DISK_BYTES = 32M
SIGNETFS   = python3 tools/signetfs.py
QEMU_DISK  = -global virtio-mmio.force-legacy=false \
             -drive file=$(DISK_IMG),if=none,format=raw,id=hd0,file.locking=off \
             -device virtio-blk-device,drive=hd0,bus=virtio-mmio-bus.0

ASM_SRCS = kernel/boot.S \
           kernel/early_trap.S \
           kernel/switch.S \
           kernel/boot_images.S

CXX_SRCS = kernel/kstring.cpp \
           kernel/platform.cpp \
           kernel/vm.cpp \
           kernel/uart.cpp \
           kernel/trap.cpp \
           kernel/frame.cpp \
           kernel/quota.cpp \
           kernel/compartment.cpp \
           kernel/revoke.cpp \
           kernel/sentry.cpp \
           kernel/thread.cpp \
           kernel/syscall.cpp \
           kernel/inspect.cpp \
           kernel/init.cpp \
           kernel/main.cpp

OBJS = $(patsubst %.S,%.o,$(ASM_SRCS)) $(patsubst %.cpp,%.o,$(CXX_SRCS))
DEPS = $(OBJS:.o=.d) $(COMP_OBJS:.o=.d)

all: signetos.elf $(DISK_IMG)

# -MMD -MP emits a .d file listing the headers each object depends on, so
# editing a header rebuilds what includes it. Without this the pure-header
# subsystems (sealing.hpp, pool.hpp, types.hpp) never trigger a rebuild.
%.o: %.S
	$(AS) $(ASFLAGS) -MMD -MP -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

# All compartments (`boot/` and `external/`) include the shared user runtime
# (`runtime.hpp`, `abi.hpp`) from `user/` and link with `user/entry.o` and
# `user/compartment.ld`.
boot/%.o: boot/%.cpp
	$(CXX) $(CXXFLAGS) -Iuser -MMD -MP -c $< -o $@

boot/%.elf: user/entry.o boot/%.o user/compartment.ld
	$(CXX) $(CXXFLAGS) $(USER_LDFLAGS) user/entry.o boot/$*.o -o $@

boot/%.bin: boot/%.elf
	$(OBJCOPY) -O binary $< $@

external/services/%.o: external/services/%.cpp
	$(CXX) $(CXXFLAGS) -Iuser -MMD -MP -c $< -o $@

external/services/%.elf: user/entry.o external/services/%.o user/compartment.ld
	$(CXX) $(CXXFLAGS) $(USER_LDFLAGS) user/entry.o external/services/$*.o -o $@

external/services/%.bin: external/services/%.elf
	$(OBJCOPY) -O binary $< $@

external/apps/%.o: external/apps/%.cpp
	$(CXX) $(CXXFLAGS) -Iuser -MMD -MP -c $< -o $@

external/apps/%.elf: user/entry.o external/apps/%.o user/compartment.ld
	$(CXX) $(CXXFLAGS) $(USER_LDFLAGS) user/entry.o external/apps/$*.o -o $@

external/apps/%.bin: external/apps/%.elf
	$(OBJCOPY) -O binary $< $@

kernel/boot_images.o: kernel/boot_images.S $(BOOT_BINS)
	$(AS) $(ASFLAGS) -MMD -MP -c $< -o $@

signetos.elf: $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(OBJS) -o $@

# The disk image is a build product like the kernel: it carries the services
# `init` loads from it and the programs the shell can run, so it is remade
# whenever one of them changes. Two `put`s: the system
# images go in `/`, where only the root quota is rooted and so out of the
# shell's sight; the programs go in `/bin`, which the shell reads through a
# read-only quota rooted there.
$(DISK_IMG): $(EXT_SERVICE_BINS) $(EXT_APP_BINS) tools/signetfs.py
	$(SIGNETFS) put $@ --size $(DISK_BYTES) $(EXT_SERVICE_BINS)
	$(SIGNETFS) put $@ --dir bin $(EXT_APP_BINS)

SMP ?= 4

# Interactive console: the production image with the serial port on this
# terminal, same as run_signetos_terminal.sh. Ctrl+A then X quits QEMU.
# Combine with TRACE_SWITCH=1 to watch the scheduler at the `SignetOS>` prompt.
term: signetos.elf $(DISK_IMG)
	$(QEMU) -bios none -machine virt -smp $(SMP) -m 2G -cpu $(QEMU_CPU) \
	  $(QEMU_DISK) \
	  -kernel signetos.elf -nographic -serial mon:stdio

clean:
	rm -f $(OBJS) $(DEPS) $(COMP_OBJS) $(COMP_ELFS) $(COMP_BINS) signetos.elf \
	      kernel/*.o kernel/*.d user/*.o user/*.d \
	      boot/*.o boot/*.d boot/*.elf boot/*.bin \
	      external/services/*.o external/services/*.d external/services/*.elf external/services/*.bin \
	      external/apps/*.o external/apps/*.d external/apps/*.elf external/apps/*.bin \
	      $(FLAGS_STAMP)

.SECONDARY: $(COMP_OBJS) $(COMP_ELFS) $(COMP_BINS)
-include $(DEPS)

.PHONY: all clean term disk

# (Re)write the disk image on its own.
disk: $(DISK_IMG)

# Objects whose contents depend on TRACE_SWITCH are rebuilt
# whenever a flag flips, via a stamp file that only changes when a value does.
FLAGS_STAMP = .build_flags
FLAG_VALUES = $(TRACE_SWITCH)
$(FLAGS_STAMP): FORCE
	@echo $(FLAG_VALUES) | cmp -s - $@ 2>/dev/null || echo $(FLAG_VALUES) > $@
kernel/thread.o: $(FLAGS_STAMP)
FORCE:
.PHONY: FORCE
