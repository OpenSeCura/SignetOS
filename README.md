<p align="center">
  <img src="assets/signetos_logo.gif" alt="SignetOS Boot Animation" width="680">
</p>

# SignetOS (Work in Progress!!)

A capability-based microkernel for pure-capability CHERI RISC-V (RV64,
`-mabi=l64pc128d`), run under QEMU.

SignetOS depends on **Zyseal**, a CHERI RISC-V sealing extension that isn't
ratified (the `YSEAL`/`YUNSEAL` instructions), on **sentries**, a QEMU
extension that makes return addresses local return sentries, and on
**mmodemmu**, a QEMU extension that lets machine mode use the MMU (SignetOS
runs entirely in M-mode). No released CHERI toolchain has them, so you first
build a patched LLVM and QEMU with [`toolchain/setup.sh`](toolchain/setup.sh).

SignetOS design and vision can be found [here](DESIGN.md).

## 1. Build the CHERI toolchain

Install the prerequisites (Debian/Ubuntu), then run the toolchain setup
script from the repository root:

```bash
sudo apt install -y cmake ninja-build clang lld python3 pkg-config \
                    libglib2.0-dev libpixman-1-dev flex bison

toolchain/setup.sh
```

The script takes about an hour and ~30 GB of disk, nearly all of it LLVM. It:

1. uses [cheribuild](https://github.com/CTSRD-CHERI/cheribuild) to fetch the
   upstream CHERI LLVM and QEMU, and copies them to `~/cheri/zyseal/`;
2. runs the extension scripts, which only apply patches to those copies:
   [`toolchain/zyseal/setup.sh`](toolchain/zyseal/setup.sh) (Zyseal, LLVM and
   QEMU), [`toolchain/mmodemmu/setup.sh`](toolchain/mmodemmu/setup.sh)
   (M-mode MMU, QEMU) and [`toolchain/sentries/setup.sh`](toolchain/sentries/setup.sh)
   (call and local return sentries, QEMU);
3. builds the patched LLVM and QEMU.

If it stops partway, run it again: steps that are already done are skipped.
See [`toolchain/README.md`](toolchain/README.md) for details.

Everything goes into `~/cheri` by default (set `CHERI_ROOT` to change that).
SignetOS uses these two outputs:

```
~/cheri/zyseal/llvm-build/bin/                         clang, ld.lld, llvm-objcopy, ...
~/cheri/zyseal/qemu-build/qemu-system-riscv64cheristd  emulator
```

## 2. Build and run SignetOS

From the repository root:

```bash
./run_signetos_terminal.sh
```

This does a clean build of the kernel and the disk image, then boots it in
QEMU with the serial console on your terminal. At the `SignetOS>` prompt,
`help` lists the commands. Type `shutdown` to power off, or press **Ctrl+A**
then **X** to kill QEMU.

You can also use `make` directly:

| Command | What it does |
|---|---|
| `make` | build `signetos.elf` and `disk.img` |
| `make term` | build if needed, then boot in QEMU on this terminal |
| `make TRACE_SWITCH=1 term` | the same, but log every thread switch |
| `make disk` | rewrite `disk.img` only |
| `make clean` | remove build outputs (keeps `disk.img`) |

`SMP=<n>` sets the number of harts (default 4). `disk.img` keeps any files the
system wrote on earlier boots; delete it to start fresh.

### Toolchain location

The Makefile finds the toolchain through `CHERI_ROOT`, which defaults to
`~/cheri`, the same default as `toolchain/setup.sh`. If you ran it with a
different `CHERI_ROOT`, use the same value here:

```bash
export CHERI_ROOT=/opt/cheri
./run_signetos_terminal.sh
```

If your binaries live somewhere else entirely, set `CHERI_SDK_BIN` (the
directory that contains `clang`) and `QEMU` (the full path to
`qemu-system-riscv64cheristd`) instead.

## Troubleshooting

- **`CHERI clang not found at ...`**: the toolchain isn't where the Makefile
  is looking. Run `toolchain/setup.sh` (step 1) or set `CHERI_ROOT`.
- **clang rejects `-march=rv64gc_zcheripurecap_zyseal`**: you're using an
  unpatched compiler. Use the one from `$CHERI_ROOT/zyseal/llvm-build/bin`.
- **QEMU rejects `Zyseal=on` or `mmodemmu=on`**: you're using an unpatched
  QEMU. Use `$CHERI_ROOT/zyseal/qemu-build/qemu-system-riscv64cheristd`.

## Layout

```
kernel/      the microkernel (boot, VM, traps, threads, sealing, syscalls), with
             hw/ (uart, clint, DTB), debug/ (reports, checks, self-tests)
             and lib/ (kstring) around it
include/     kernel headers and a minimal freestanding libc
user/        runtime and linker script shared by all user compartments
boot/        compartments embedded in the kernel: init, fs, uart, blk
external/    compartments loaded from disk.img: services/ (naming, sealer,
             sched, trap_mgr, shell) and apps/ (programs the shell can `run`)
tools/       signetfs.py, which writes disk.img
toolchain/   patches and scripts that build the CHERI LLVM and QEMU (Zyseal,
             mmodemmu, sentries)
```
