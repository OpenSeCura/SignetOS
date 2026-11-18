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
# instructions, the SE/US permissions, and a 5-bit CT field. Zyseal is a local
# non-ratified dialect; toolchain/setup.sh fetches, patches and builds the
# toolchain (see README.md).
#
# Zyseal is mandatory. The kernel's object model is hardware sealing and there
# is no software fallback.
#
# Zylevels1=on enables CHERI capability levels (the GL flag plus the LG/SL
# permissions). QEMU's `rv64` model has it off by default
# and only then advertises `zcherilevels` in the device tree. The kernel keeps
# the three bits on every derivation (`perms::Levels`, `KERNEL_LEVEL_PERMS`) so
# it boots either way. MARCH stays
# without `_zcherilevels` on purpose: the flag changes no code generation, only
# whether the toolchain defines the level macros, and both headers fall back
# to the fixed ISA bit positions.
#
# sentries=on (toolchain/sentries) makes the link a call writes a return sentry
# (CT 2). Only a return can use one, a return can use nothing else, and it is
# local, so only a stack can hold it. Code never runs from a local capability.
# It also leaves `yseal`, under an authority only the kernel holds, the one way
# to make a call sentry (CT 1); without it the kernel cannot seal the switcher
# gate and stops at boot. It needs Zylevels1.
#
# mmodemmu=on (toolchain/mmodemmu) lets M-mode use the MMU. The kernel and
# every compartment run in M-mode, so this is what keeps paging; without it
# the kernel's first access to the mmodemmu CSR is an illegal instruction.
#
# Svucrg=on gives each page two capability bits the hardware reads: whether it
# may hold capabilities, and its capability load generation. mmodecrg=on
# (toolchain/mmodecrg) makes the generation check apply to M-mode's pages,
# which Svucrg leaves out. Every mapping that holds capabilities carries
# pte::CapWrite (vm.hpp); a kernel without it cannot store a capability under
# Svucrg and stops at boot.
#
# CHERI_ROOT is the install root toolchain/setup.sh used (its default is
# ~/cheri); the patched tools are under $(CHERI_ROOT)/zyseal. Override it (or
# CHERI_SDK_BIN / QEMU individually) on the command line or in the environment
# to use a toolchain somewhere else.
# ---------------------------------------------------------------------------
CHERI_ROOT    ?= $(HOME)/cheri
CHERI_SDK_BIN ?= $(CHERI_ROOT)/zyseal/llvm-build/bin
QEMU          ?= $(CHERI_ROOT)/zyseal/qemu-build/qemu-system-riscv64cheristd
MARCH         = rv64gc_zcheripurecap_zyseal
QEMU_CPU      = rv64,Zyseal=on,Zylevels1=on,sentries=on,mmodemmu=on,Svucrg=on,mmodecrg=on
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
toolchain/setup.sh, or set CHERI_ROOT / CHERI_SDK_BIN)
endif
endif

OPT ?= -O2

# TRACE_SWITCH=1 makes the kernel print one line on the UART for every
# successful `sys_thread_switch` (`debug::trace_switch`, called from
# `__signetos_thread_dispatch` in `kernel/thread.cpp`).
# Every switch the scheduler compartment makes -- dispatcher, yield and the
# timer tick -- goes through it, so it sees them all. Off by default.
TRACE_SWITCH ?= 0
ifeq ($(TRACE_SWITCH),1)
TRACE_DEFS = -DSIGNETOS_TRACE_SWITCH
else
TRACE_DEFS =
endif

# QUOTA_SELFTEST=1 runs `debug::quota_self_test` (`kernel/debug/quota_selftest.cpp`)
# at boot, before `init` starts, and panics on the first failed check. Off by default.
QUOTA_SELFTEST ?= 0
ifeq ($(QUOTA_SELFTEST),1)
TEST_DEFS = -DSIGNETOS_QUOTA_SELFTEST
else
TEST_DEFS =
endif

# SWEEP_STRESS=1 keeps a revocation sweep running all the time and makes each
# one slow, so that most pages are stale most of the time (vm.hpp, CHECKED
# PAGES): the sweeper starts the next sweep as soon as one completes and
# checks one page every few milliseconds, and a sweep is started whether or
# not there is anything to revoke. Every path that loads capabilities then
# meets stale pages, including the ones the kernel has to check for itself
# (revoke.hpp, KERNEL LOADS), where one that was missed halts the machine
# with a load page fault raised by kernel code. A test build: off by default.
SWEEP_STRESS ?= 0
ifeq ($(SWEEP_STRESS),1)
TEST_DEFS += -DSIGNETOS_SWEEP_STRESS
endif

# SMP_SELFTEST=1 runs `debug::smp_self_test` (`kernel/debug/smp_selftest.cpp`)
# at boot: one of the parked harts is given a thread to run, a sweep is
# started under it, and the thread stays there, stopped by every sweep the
# system starts, until power-off (revoke.hpp, SEVERAL HARTS). The only build
# in which a hart other than the boot hart runs a thread. Needs SMP >= 2. A
# test build: off by default.
SMP_SELFTEST ?= 0
ifeq ($(SMP_SELFTEST),1)
TEST_DEFS += -DSIGNETOS_SMP_SELFTEST
endif

# PAGING=1 (the default): what compartments allocate can go to swap and back
# (vm.hpp, PAGING). PAGING=0 builds everything without it: the kernel has no
# paging code and no paging system calls, `blk` no pager, the disk image no
# swap, and every page in use is in RAM. SWAP_HASH and PAGE_TEST are
# paging's, and do nothing without it.
PAGING ?= 1

# SWAP_HASH=1 (the default): the kernel keeps a BLAKE2b-256 digest of every
# page it sends to disk and refuses a copy that comes back different, so
# `blk` cannot change a page or have a capability built that was not there
# (vm.hpp, PAGING). SWAP_HASH=0 drops it, and trusts `blk` with those.
SWAP_HASH ?= 1

# PAGE_TEST=1 builds in sys_page_test, which the shell's `pagetest` needs:
# the kernel's paging counters, and sending chosen pages to swap. Off by
# default; without it the call refuses everything.
PAGE_TEST ?= 0

PAGING_DEFS =
PAGING_SRCS =
ifeq ($(PAGING),1)
PAGING_DEFS += -DSIGNETOS_PAGING
PAGING_SRCS += kernel/paging.cpp
ifeq ($(SWAP_HASH),1)
PAGING_DEFS += -DSIGNETOS_SWAP_HASH
PAGING_SRCS += kernel/lib/blake2b.cpp
endif
ifeq ($(PAGE_TEST),1)
PAGING_DEFS += -DSIGNETOS_PAGE_TEST
endif
endif

CXXFLAGS = -target riscv64-unknown-freebsd -march=$(MARCH) -mabi=l64pc128d \
           -std=c++20 -ffreestanding -nostdlib -nostdinc++ -nostdinc -U__FreeBSD__ \
           -fno-exceptions -fno-rtti -fno-unwind-tables -fno-asynchronous-unwind-tables \
           -fno-threadsafe-statics -fno-use-cxa-atexit -fno-common -fno-jump-tables \
           -mcmodel=medany $(OPT) -Wall -Wextra \
           -Wno-cheri-capability-misuse -Wno-cheri-implicit-conversion -Wno-cheri-pointer-conversion \
           -Iinclude -Iinclude/libc -g $(TRACE_DEFS) $(TEST_DEFS) $(PAGING_DEFS)

ASFLAGS  = -target riscv64-unknown-freebsd -march=$(MARCH) -mabi=l64pc128d \
           -mcmodel=medany -ffreestanding -nostdlib -nostdinc -U__FreeBSD__ \
           -Iinclude -Iinclude/libc -g

LDFLAGS      = -fuse-ld=lld -T kernel/linker.ld -nostdlib -static -Wl,--local-caprelocs=legacy $(EXTRA_LDFLAGS)
USER_LDFLAGS = -fuse-ld=lld -T user/compartment.ld -nostdlib -static -Wl,--local-caprelocs=legacy

# Standalone user-space compartments, compiled and linked separately into
# flat binaries using the shared runtime in `user/`.
#
# `boot/` (`BOOT_COMPS`): embedded into the kernel via `kernel/boot_images.S`
# -- `init` and what it needs to reach the disk (`uart`, `blk`, `fs`), and
# the loader every compartment made from an image runs first (loader.hpp).
#
# `external/` (`EXT_SERVICES` and `EXT_APPS`): written into `disk.img` at build
# time by `tools/signetfs.py` (never linked into the kernel image).
#   - `external/services/`: root-owned system services (`naming`, `sealer`,
#     `sched`, `sweeper`, `shell`) that `init` reads from `fs` out of `/` and
#     loads.
#   - `external/apps/`: programs, written to `/bin`, which the shell can
#     `run` (user/launch.hpp); each one's manifest says what it asks for.
BOOT_COMPS = init loader fs uart dma blk
BOOT_SRCS  = $(patsubst %,boot/%.cpp,$(BOOT_COMPS))
BOOT_OBJS  = $(patsubst %.cpp,%.o,$(BOOT_SRCS))
BOOT_ELFS  = $(patsubst %,boot/%.elf,$(BOOT_COMPS))
BOOT_BINS  = $(patsubst %,boot/%.bin,$(BOOT_COMPS))

EXT_SERVICES     = naming sealer sched sweeper shell
EXT_SERVICE_SRCS = $(patsubst %,external/services/%.cpp,$(EXT_SERVICES))
EXT_SERVICE_OBJS = $(patsubst %.cpp,%.o,$(EXT_SERVICE_SRCS))
EXT_SERVICE_ELFS = $(patsubst %,external/services/%.elf,$(EXT_SERVICES))
EXT_SERVICE_BINS = $(patsubst %,external/services/%.bin,$(EXT_SERVICES))

EXT_APPS     = hello logo fault sealtest
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

# Swap: a region at the end of disk.img, after the file system, described by
# the image's last sector (`tools/signetfs.py swap`). Pageable memory goes
# there once RAM is full, and there can be no more of it than swap holds
# (vm.hpp, PAGING). SWAP_BYTES=0: no swap, no paging.
# With less RAM than swap (MEM, below) memory really pages:
# `make term MEM=128M PAGE_TEST=1`, then `pagetest fill 112` in the shell.
ifeq ($(PAGING),1)
SWAP_BYTES ?= 256M
else
SWAP_BYTES ?= 0
endif
SIGNETFS   = python3 tools/signetfs.py
QEMU_DISK  = -global virtio-mmio.force-legacy=false \
             -drive file=$(DISK_IMG),if=none,format=raw,id=hd0,file.locking=off \
             -device virtio-blk-device,drive=hd0,bus=virtio-mmio-bus.0

ASM_SRCS = kernel/boot.S \
           kernel/early_trap.S \
           kernel/switch.S \
           kernel/sweep.S \
           kernel/debug/smp_stub.S \
           kernel/boot_images.S

# The core kernel is kernel/*.cpp. Around it: hardware drivers (kernel/hw/),
# diagnostics and self-tests (kernel/debug/) and freestanding C library
# routines (kernel/lib/).
CXX_SRCS = kernel/vm.cpp \
           kernel/trap.cpp \
           kernel/irq.cpp \
           kernel/frame.cpp \
           kernel/quota.cpp \
           kernel/compartment.cpp \
           kernel/loader.cpp \
           kernel/revoke.cpp \
           kernel/sentry.cpp \
           kernel/switcher.cpp \
           kernel/thread.cpp \
           kernel/smp.cpp \
           kernel/unwind.cpp \
           kernel/syscall.cpp \
           kernel/init.cpp \
           kernel/main.cpp \
           kernel/hw/platform.cpp \
           kernel/hw/clint.cpp \
           kernel/hw/uart.cpp \
           kernel/debug/report.cpp \
           kernel/debug/inspect.cpp \
           kernel/debug/quota_selftest.cpp \
           kernel/debug/smp_selftest.cpp \
           kernel/lib/kstring.cpp \
           $(PAGING_SRCS)

OBJS = $(patsubst %.S,%.o,$(ASM_SRCS)) $(patsubst %.cpp,%.o,$(CXX_SRCS))
DEPS = $(OBJS:.o=.d) $(COMP_OBJS:.o=.d)

all: signetos.elf $(DISK_IMG)

# -MMD -MP emits a .d file listing the headers each object depends on, so
# editing a header rebuilds what includes it. Without this the pure-header
# subsystems (sealing.hpp, types.hpp) never trigger a rebuild.
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
# whenever one of them changes. System images go in `/` (only `init` has a
# handle to it) and programs in `/bin`.
$(DISK_IMG): $(EXT_SERVICE_BINS) $(EXT_APP_BINS) tools/signetfs.py
	$(SIGNETFS) put $@ --size $(DISK_BYTES) $(EXT_SERVICE_BINS)
	$(SIGNETFS) put $@ --dir bin $(EXT_APP_BINS)
	$(SIGNETFS) swap $@ --size $(SWAP_BYTES)

SMP ?= 4
MEM ?= 2G

# Interactive console: the production image with the serial port on this
# terminal, same as run_signetos_terminal.sh. Ctrl+A then X quits QEMU.
# Combine with TRACE_SWITCH=1 to watch the scheduler at the `SignetOS>` prompt.
term: signetos.elf $(DISK_IMG)
	$(QEMU) -bios none -machine virt -smp $(SMP) -m $(MEM) -cpu $(QEMU_CPU) \
	  $(QEMU_DISK) \
	  -kernel signetos.elf -nographic -serial mon:stdio

clean:
	rm -f $(OBJS) $(DEPS) $(COMP_OBJS) $(COMP_ELFS) $(COMP_BINS) signetos.elf \
	      kernel/*.o kernel/*.d kernel/*/*.o kernel/*/*.d user/*.o user/*.d \
	      boot/*.o boot/*.d boot/*.elf boot/*.bin \
	      external/services/*.o external/services/*.d external/services/*.elf external/services/*.bin \
	      external/apps/*.o external/apps/*.d external/apps/*.elf external/apps/*.bin \
	      $(FLAGS_STAMP)

.SECONDARY: $(COMP_OBJS) $(COMP_ELFS) $(COMP_BINS)
-include $(DEPS)

.PHONY: all clean term disk

# (Re)write the disk image on its own.
disk: $(DISK_IMG)

# Everything is rebuilt, and the disk image remade, whenever one of
# TRACE_SWITCH, QUOTA_SELFTEST, SWEEP_STRESS, SMP_SELFTEST, PAGING, SWAP_HASH,
# PAGE_TEST or SWAP_BYTES
# flips, via a stamp file that only changes when a value does. Everything,
# because PAGING changes the system call list every object is built against.
FLAGS_STAMP = .build_flags
FLAG_VALUES = $(TRACE_SWITCH) $(QUOTA_SELFTEST) $(PAGING) $(SWAP_HASH) \
              $(PAGE_TEST) $(SWAP_BYTES) $(SWEEP_STRESS) $(SMP_SELFTEST)
$(FLAGS_STAMP): FORCE
	@echo $(FLAG_VALUES) | cmp -s - $@ 2>/dev/null || echo $(FLAG_VALUES) > $@
$(OBJS) $(COMP_OBJS): $(FLAGS_STAMP)
$(DISK_IMG): $(FLAGS_STAMP)
FORCE:
.PHONY: FORCE
