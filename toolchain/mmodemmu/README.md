# mmodemmu: let M-mode use the MMU

A local, **not ratified** extension that lets machine mode use the MMU. It is
for a single-privilege system: kernel and compartments all run in M-mode, the
CHERI ASR permission is the only privilege boundary, and paging still works.
`patches/` adds it to QEMU. LLVM needs no change, because the CSR is
accessed by number.

```
setup.sh     applies the patches to the QEMU tree (run by ../setup.sh)
patches/     01-qemu-mmodemmu (6 files)
```

`../setup.sh` runs `./setup.sh` after the Zyseal patches and before it builds
QEMU, so the patch sits on top of Zyseal in the same QEMU copy
(`$CHERI_ROOT/zyseal/qemu`). A patch that is already applied is skipped.

## The extension

- **Enabling it:** `-cpu rv64,...,mmodemmu=on`. It is off by default.
- **Without it:** the `mmodemmu` CSR does not exist, and any access is an
  illegal instruction.
- **Detecting it:** software probes by reading the CSR. It is not listed in
  `riscv,isa`, whose grammar has no place for the name.

### The `mmodemmu` CSR (`0x7c0`)

- **Access:** `0x7c0` is in the custom machine read/write range, so only
  M-mode can reach it. With CHERI, reads and writes need ASR, as for every
  machine CSR.
- **Behaviour:** WARL. It resets to 0, which is stock behaviour.

| bit | name | meaning |
|---|---|---|
| 0 | `ENABLE` | M-mode accesses go through the MMU (`satp`) |

All other bits read as zero.

### `ENABLE`

When `ENABLE` is set and `satp.MODE` is not Bare, M-mode instruction fetches
and data accesses are translated through `satp`:

- **Permissions.** S-mode rules apply:
  - a U page needs `mstatus.SUM` for loads and stores;
  - a U page is never executable;
  - `MXR` applies.
- **MPRV.** Loads and stores still take the mode in `MPP` while `MPRV` is
  set. With `MPP` = M, they are translated as above.
- **Page faults.** Causes 12, 13 and 15 are taken in M-mode, with the
  faulting VA in `mtval`. Nothing below M-mode can take them.
- **PMP.** The final physical address is checked at M, as for any M-mode
  access. The walk's own PTE reads are also checked at M, the way an S-mode
  walk's are checked at S. An M-mode walk therefore needs no PMP entry.
- **TLB.** Changing `ENABLE` flushes the hart's TLB, and the next
  instruction is fetched under the new setting. Software must keep the code
  doing the switch mapped (identity-map it). `satp` and `SFENCE.VMA` work as
  usual.

### What code without ASR can do in M-mode

| Action | Result |
|---|---|
| Read or write any S, H or M CSR, including `mmodemmu` and `satp` | CHERI fault (needs ASR) |
| `MRET`, `SRET` | CHERI fault (needs ASR) |
| `WFI` | Allowed, but it idles only until the next interrupt enabled in `mie`, which only the kernel can write. A spin loop already gives a compartment that much. |
| `SFENCE.VMA` | Allowed. It only invalidates the TLB, so it can cost performance but not correctness, as compartments in S-mode can already do today. |
| `ECALL` | Cause 11, an ordinary exception to the kernel |
| Any exception | Taken by the kernel in M-mode; nothing can be delegated away |
| PMP | Does not constrain M-mode (unlocked entries), so nothing is lost against an open PMP |

## Status in SignetOS

SignetOS runs entirely in M-mode on it: kernel and compartments, with no
S-mode and no firmware. `QEMU_CPU` in the top-level `Makefile` sets
`mmodemmu=on`; every hart sets `ENABLE` once `satp` is programmed
(`vm::init`, and `.Lsecondary_start` in `kernel/boot.S`).
