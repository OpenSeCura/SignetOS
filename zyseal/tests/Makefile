 #
 # Copyright 2026 Google LLC (Cherified Team)
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
 #

# Zyseal test suite.
#
# Needs the PATCHED clang and the PATCHED qemu (see ../README.md).
# Override any of these on the command line or in the environment:
#
#   make CHERI_ROOT=/somewhere/else
#   make ZYSEAL_LLVM=/path/to/llvm-build ZYSEAL_QEMU=/path/to/qemu-build
#
CHERI_ROOT  ?= $(HOME)/cheri

ZYSEAL_LLVM ?= $(CHERI_ROOT)/zyseal/llvm-build
ZYSEAL_QEMU ?= $(CHERI_ROOT)/zyseal/qemu-build

# OpenSBI firmware, built by cheribuild's
# cheri-std093-opensbi-baremetal-riscv64-purecap target.
BIOS ?= $(CHERI_ROOT)/build/cheri-std093-opensbi-baremetal-riscv64-purecap-std093-build/platform/generic/firmware/fw_jump.bin

# Unpatched upstream QEMU, if you have one. Only used by `make run-stockqemu`.
STOCK_QEMU  ?= $(CHERI_ROOT)/output/sdk/bin/qemu-system-riscv64cheristd

CLANG   := $(ZYSEAL_LLVM)/bin/clang
OBJDUMP := $(ZYSEAL_LLVM)/bin/llvm-objdump
READELF := $(ZYSEAL_LLVM)/bin/llvm-readelf
QEMU    := $(ZYSEAL_QEMU)/qemu-system-riscv64cheristd

# Override with zyseal0p9 if the bare name is rejected.
ARCH ?= rv64gc_zcheripurecap_zyseal

CFLAGS := \
  -target riscv64-unknown-freebsd \
  -march=$(ARCH) \
  -mabi=l64pc128d \
  -mcmodel=medany \
  -ffreestanding -nostdlib -nostdinc \
  -U__FreeBSD__ \
  -fno-common -fno-jump-tables \
  -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -O1 -g -ffixed-x25 \
  -Wall -Wextra \
  -Wno-cheri-capability-misuse \
  -Wno-cheri-implicit-conversion \
  -Wno-cheri-pointer-conversion

ASFLAGS := -target riscv64-unknown-freebsd -march=$(ARCH) -mabi=l64pc128d -mcmodel=medany -c
LDFLAGS := -fuse-ld=lld -B$(ZYSEAL_LLVM)/bin -T link.ld -nostdlib -static \
           -Wl,--local-caprelocs=legacy

OBJS := boot.o trap.o tests.o

all: tests.elf

check-toolchain:
	@test -x $(CLANG) || { echo "no clang at $(CLANG) -- set ZYSEAL_LLVM"; exit 1; }
	@test -x $(QEMU)  || { echo "no qemu at $(QEMU) -- set ZYSEAL_QEMU"; exit 1; }
	@test -f $(BIOS)  || { echo "no firmware at $(BIOS) -- set BIOS"; exit 1; }
	@echo "toolchain ok"

trap.o: trap.S
	$(CLANG) $(ASFLAGS) -o $@ $<

boot.o: boot.S
	$(CLANG) $(ASFLAGS) -o $@ $<

tests.o: tests.c
	$(CLANG) $(CFLAGS) -c -o $@ $<

tests.elf: $(OBJS) link.ld
	$(CLANG) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

QFLAGS := -bios $(BIOS) -machine virt -m 2G -kernel tests.elf -nographic -monitor none

# 58 passed, 0 failed
run: tests.elf
	@rm -f out.txt
	-timeout 25s $(QEMU) $(QFLAGS) -cpu rv64,Zyseal=on -serial file:out.txt
	@sed -n '/flat inline-assembly/,$$p' out.txt

# 65 passed, 0 failed. The only configuration in which spec 17.6.2 (yunseal
# clears GL for a local authority) has any content; T29 skips itself without it.
run-levels: tests.elf
	@rm -f out-levels.txt
	-timeout 25s $(QEMU) $(QFLAGS) -cpu rv64,Zyseal=on,Zylevels1=on -serial file:out-levels.txt
	@sed -n '/flat inline-assembly/,$$p' out-levels.txt

# Negative control. trap.S resumes at sepcc+4, so instead of dying the program
# skips every yseal/yunseal and leaves the destination register untouched:
# tests that depend on a sealing instruction fail, the rest still pass.
run-nozyseal: tests.elf
	@rm -f out-nozyseal.txt
	-timeout 15s $(QEMU) $(QFLAGS) -cpu rv64 -serial file:out-nozyseal.txt
	@sed -n '/flat inline-assembly/,$$p' out-nozyseal.txt | head -20

# Stronger negative control, if you kept an unpatched QEMU: -cpu rv64,Zyseal=on
# is rejected outright there, because the property does not exist.
run-stockqemu: tests.elf
	@test -x $(STOCK_QEMU) || { echo "no unpatched qemu at $(STOCK_QEMU) -- set STOCK_QEMU"; exit 1; }
	@echo "=== does the unpatched build have the Zyseal property? ==="
	-@timeout 20s $(STOCK_QEMU) $(QFLAGS) -cpu rv64,Zyseal=on -serial file:/dev/null 2>&1 | head -2

# Everything including OpenSBI's output, for when something dies before main.
run-full: tests.elf
	@rm -f out.txt
	-timeout 25s $(QEMU) $(QFLAGS) -cpu rv64,Zyseal=on -serial file:out.txt
	@cat out.txt

# Did the new instructions actually reach the binary?
verify: tests.elf
	@echo "=== yseal / yunseal occurrences ==="
	@$(OBJDUMP) -d --mattr=+zcheripurecap,+zyseal tests.elf | grep -nE "\<y(un)?seal\>" || echo "NONE FOUND"
	@echo "=== __cap_relocs size (should be small or empty) ==="
	@$(READELF) -S tests.elf | grep -A1 cap_relocs || true

# Disassemble test_main so the inline asm can be checked line-for-line against
# what the assembler emitted.
show: tests.elf
	@$(OBJDUMP) -d --mattr=+zcheripurecap,+zyseal tests.elf \
	  | awk '/<test_main>:/,/^$$/'

clean:
	rm -f $(OBJS) tests.elf out.txt out-levels.txt out-nozyseal.txt

.PHONY: all check-toolchain verify run run-levels run-nozyseal run-stockqemu run-full show clean
