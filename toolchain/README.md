# Toolchain

SignetOS needs a CHERI LLVM and QEMU with local, **non-ratified** extensions.
No released CHERI toolchain has them, so this directory builds patched ones.

```
setup.sh     fetches, copies, patches and builds the whole toolchain
zyseal/      Zyseal sealing extension: LLVM and QEMU patches, tests
mmodemmu/    lets M-mode use the MMU: one QEMU patch
sentries/    call sentries and local return sentries: one QEMU patch
```

From the repository root:

```bash
sudo apt install -y cmake ninja-build clang lld python3 pkg-config \
                    libglib2.0-dev libpixman-1-dev flex bison

toolchain/setup.sh         # installs under $CHERI_ROOT, default ~/cheri
```

About an hour and ~30 GB of disk the first time, nearly all of it LLVM.
`setup.sh`:

1. clones [cheribuild](https://github.com/CTSRD-CHERI/cheribuild) and uses it
   to build upstream CHERI LLVM and the OpenSBI firmware, and to fetch the
   QEMU source;
2. copies the LLVM and QEMU trees to `$CHERI_ROOT/zyseal/`, so cheribuild's
   originals stay untouched;
3. runs each extension's `setup.sh` to patch the copies, in order:
   `zyseal/`, then `mmodemmu/`, then `sentries/` (each QEMU patch goes on
   top of the ones before it);
4. builds the patched LLVM and QEMU.

**Re-running** is safe. Finished steps are skipped, a patch that is already
applied is skipped, and the builds are incremental.

**Extension scripts** only apply patches, so running one on its own needs a
rebuild afterwards. Re-running `setup.sh` does that.

The patched tools end up in:

```
$CHERI_ROOT/zyseal/llvm-build/bin/                         clang, ld.lld, ...
$CHERI_ROOT/zyseal/qemu-build/qemu-system-riscv64cheristd  emulator
```
