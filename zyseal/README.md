# Zyseal

Implementation of the CHERI RISC-V `Zyseal` sealing
extension (spec Chapter 17) for QEMU and LLVM, plus a test suite. No QEMU or
LLVM source is included; `setup.sh` fetches and patches it. Please note that
Zyseal is not ratified and is subject to change. The way we have implemented
it also allows the number of CT bits to increase should your usecase require
more hardware otypes. NOTE: what CHERI folks normally refer to as the otype,
CHERI RISC-V calls CT bits ie. capability type.

```
setup.sh     fetch the upstream toolchain, patch it, build it
patches/     01-qemu (10 files), 02-llvm (7 files), 03-llvm-sealed-get-fix (1 file)
tests/       test suite
```

`03-llvm-sealed-get-fix.patch` is unrelated to Zyseal: upstream
`__builtin_cheri_sealed_get()` returned the raw otype instead of a boolean.

## The extension

### Capability layout

The 128-bit `128r` format. Bits 0–63 are the address; the metadata is:

| bits | field | |
|---|---|---|
| 127–124 | SDP | software permissions |
| 123 | MODE | |
| 122–118 | RESERVED1 | |
| **117–108** | **AP** | architectural permissions — **AP[9]=US, AP[8]=SE** |
| 107 | LEVEL | |
| 106–95 | RESERVED0 | free; widening CT takes bits from here |
| **94–91** | **CT** | object type, 4 bits |
| 90–64 | EBT | bounds |

Only the two bold entries are ours. CT was widened from the base architecture's
1 bit; AP was widened from 8 bits to 10.

### Object types

| CT | meaning | dereference (`ld`/`sd`/`clc`) | `cjalr` |
|---|---|---|---|
| 0 | unsealed | allowed | allowed |
| 1 | sentry | faults | allowed iff offset 0, unsealed on arrival |
| 2–15 | sealed object | faults | faults |

14 usable types. `yseal` can only ever produce 2–15, and `yunseal` only accepts
2–15, so neither can mint or open a sentry.

### SE and US permissions

These have two distinct bit positions:

- **Stored** in the AP field, AP bits 8 (SE) and 9 (US), i.e. capability bits
  116 and 117.
- **Decoded** as bits 24 (SE) and 25 (US) of the word `gcperm` (YPERMR)
  returns and `acperm` (YPERMC) masks. Spec Figure 16.

Decoded bit *n* does not correspond to AP bit *n* — decoded bit 0 comes from AP
bit 1. `get_all_permissions()` / `set_permissions()` are the mapping.

The root capability carries SE and US.

### Instructions

Both take the **sealing authority** in `rs1`: a capability whose *address* is
the object type being named and whose *bounds* are the range of types it is
entitled to name. Neither traps; on refusal they write `rs2` to `rd` with the
tag cleared.

`yseal rd, rs1, rs2` — let `ct` = `rs1`'s address. Succeeds iff:

```
rs2.tag  &&  rs1.tag  &&  rs2 is unsealed  &&  rs1 grants SE
         &&  ct is within rs1's bounds
         &&  2 <= ct <= 15
```

Result is `rs2` with CT set to `ct`. Nothing else changes — bounds, address and
permissions are untouched.

`yunseal rd, rs1, rs2` — let `ct` = `rs1`'s address. Succeeds iff:

```
rs2.tag  &&  rs1.tag  &&  rs1 grants US
         &&  ct is within rs1's bounds
         &&  ct >= 2  &&  ct == rs2's CT
```

Exact equality, not a subset test. Result is `rs2` with CT set to 0. If
Zylevels1 is enabled and `rs1` does not grant GL, GL is cleared on the result
(§17.6.2); `yseal` has no such rule (§17.6.1).

### Encoding

Both are OP-format, funct7 `0000111`; funct3 `010` for `yseal`, `011` for
`yunseal`. So `yseal c1, c2, c3` is `0x0e3120b3`:

| 31–25 | 24–20 | 19–15 | 14–12 | 11–7 | 6–0 |
|---|---|---|---|---|---|
| `0000111` | rs2 | rs1 | `010` | rd | `0110011` |


Without `+zyseal` it must be rejected. The extension is off by default in QEMU
too, enabled with `-cpu rv64,Zyseal=on`. It is only compiled into the 64-bit
target; `rv32` accepts `Zyseal=on` but does nothing with it.

## Building

```bash
sudo apt install -y cmake ninja-build clang lld python3 pkg-config \
                    libglib2.0-dev libpixman-1-dev flex bison

./setup.sh                 # installs under $CHERI_ROOT, default $HOME/cheri
```

About an hour and ~30 GB of disk, nearly all of it LLVM. Re-running skips what
is already done. It clones
[cheribuild](https://github.com/CTSRD-CHERI/cheribuild), uses it to build
upstream LLVM and the OpenSBI firmware and to fetch the QEMU source, then
copies the LLVM and QEMU trees to `$CHERI_ROOT/zyseal/`, patches the copies and
builds them.

Upstream is `CHERI-Alliance/llvm-project` (`codasip-cheri-riscv-20`) and
`CHERI-Alliance/qemu` (`main`).


## Running the tests

```bash
cd tests
make check-toolchain     # confirms clang, qemu and the firmware are findable
make
make run                 # -cpu rv64,Zyseal=on   -> 58 passed, 0 failed
make run-levels          # ...,Zylevels1=on      -> 65 passed, 0 failed
```

The seven extra checks under `Zylevels1` cover §17.6.2, which has no content
unless capability levels are enabled; T29 detects the mode and skips itself
otherwise.

| | |
|---|---|
| `make show` | disassemble `test_main` to check the asm line-for-line |
| `make verify` | confirm `yseal`/`yunseal` really are in the binary |
| `make run-nozyseal` | negative control — without the extension, sealing-dependent tests fail and the rest still pass |
| `make run-stockqemu` | stronger control — an unpatched QEMU rejects `Zyseal=on` outright |

