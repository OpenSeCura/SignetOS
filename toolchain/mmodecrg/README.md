# mmodecrg: capability load generations for M-mode's pages

A local, **not ratified** extension. `Svucrg` gives each page a capability
load generation and traps a capability load from a page of another
generation, but only for U pages. `mmodecrg` makes that check for every page.
It is for a system that runs entirely in M-mode (`../mmodemmu`) and has no U
pages. `patches/` adds it to QEMU. LLVM needs no change.

```
setup.sh     applies the patches to the QEMU tree (run by ../setup.sh)
patches/     01-qemu-mmodecrg (3 files)
```

`../setup.sh` runs `./setup.sh` after the sentries patches and before it
builds QEMU, so the patch sits on top of them in the same QEMU copy
(`$CHERI_ROOT/zyseal/qemu`). A patch that is already applied is skipped.

## The extension

- **Enabling it:** `-cpu rv64,...,Svucrg=on,mmodecrg=on`. It is off by
  default.
- **It needs `Svucrg`:** QEMU refuses to start with `mmodecrg=on` and
  `Svucrg` off.
- **Without it:** `Svucrg` behaves as upstream: the generation check covers U
  pages only.
- **Detecting it:** software cannot. It adds no CSR and is not listed in
  `riscv,isa`.

### What `Svucrg` provides

Two bits in each leaf PTE, and one in `mstatus`:

| where | bit | name | meaning |
|---|---|---|---|
| PTE | 60 | `CW` | the page may hold capabilities |
| PTE | 59 | `CRG` | the page's capability load generation |
| `mstatus` | 61 | `UCRG` | the current generation |

- **A page without `CW`:** a store of a tagged capability is a store page
  fault (cause 15), and a capability loaded from the page comes back
  untagged. This applies to every page, U or not, with or without
  `mmodecrg`.
- **A table pointer with `CW`:** the walk fails. Only leaf entries carry it.

### What `mmodecrg` changes

The generation check:

| page | `Svucrg` alone | with `mmodecrg` |
|---|---|---|
| U page, `CW` set | checked | checked |
| page without U, `CW` set | not checked | **checked** |

A checked page whose `CRG` differs from `mstatus.UCRG` traps a load of a
**tagged** capability:

- **Cause:** load page fault (13), taken in M-mode, with the address in
  `mtval` and 1 in `mtval2`.
- **What does not trap:** loads of data, and loads of capability-sized values
  whose tag is clear.
- **Megapages:** a leaf at any level takes the same path through the check.
  SignetOS relies on it for 2 MiB leaves: its kernel image and direct map
  are mapped that way and change generation with the hart.

### TLB

- Writing `mstatus` so that `UCRG` changes flushes the hart's TLB in QEMU.
- Changing a PTE's `CW` or `CRG` needs `SFENCE.VMA`, as any PTE change does.

## Status in SignetOS

`QEMU_CPU` in the top-level `Makefile` sets `Svucrg=on,mmodecrg=on`.

- **`CW`:** the kernel sets it on every mapping that capabilities are stored
  through (`pte::CapWrite`, `include/signetos/vm.hpp`). A kernel that does not
  stops at boot under `Svucrg`.
- **`CRG` and `UCRG`:** a revocation sweep starts by flipping `UCRG`, and
  with it `CRG` on the kernel's own mappings (`pte::CapGen`; `vm.hpp`,
  CHECKED PAGES). Every other page is then of the old generation: the first
  capability load from it traps, the kernel checks the page for revoked
  capabilities, gives it the new generation, and the load runs again
  (`revoke.hpp`, A SWEEP). The step that flips them loads no capability from
  memory in between (`kernel/sweep.S`).
