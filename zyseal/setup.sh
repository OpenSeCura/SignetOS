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


#!/bin/bash
# Get the upstream CHERI toolchain with cheribuild, apply the zyseal patches,
# and build the patched LLVM and QEMU. After this, `make run` in tests/ works.
#
#   ./setup.sh                    installs under $HOME/cheri
#   CHERI_ROOT=/opt/x ./setup.sh  installs somewhere else
#
# Expect an hour or so, almost all of it LLVM. Re-running is safe: steps that
# are already done are skipped.
set -e

CHERI_ROOT=${CHERI_ROOT:-$HOME/cheri}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
JOBS=${JOBS:-$(nproc)}

BIOS=$CHERI_ROOT/build/cheri-std093-opensbi-baremetal-riscv64-purecap-std093-build/platform/generic/firmware/fw_jump.bin

echo "install root: $CHERI_ROOT"
mkdir -p "$CHERI_ROOT"

# ---------------------------------------------------------------- cheribuild
if [ ! -d "$CHERI_ROOT/cheribuild" ]; then
    echo "### cloning cheribuild"
    git clone https://github.com/CTSRD-CHERI/cheribuild.git "$CHERI_ROOT/cheribuild"
fi
CB="$CHERI_ROOT/cheribuild/cheribuild.py -d --source-root $CHERI_ROOT"

echo "### building the upstream LLVM with cheribuild"
echo "    (this is the long one)"
$CB cheri-std093-llvm

# Source only. cheribuild compiles QEMU with clang, and recent upstream QEMU
# does not build with clang 21 (const-qualifier warnings promoted to errors in
# util/log.c and dtc/libfdt). We build the patched copy ourselves below with
# gcc, which is unaffected, so the unpatched binary is never needed -- only the
# source tree and its submodules.
echo "### fetching the QEMU source"
$CB cheri-std093-qemu --configure-only

# The tests boot on fw_jump.bin. OpenSBI also builds fw_payload.elf, which we
# never use and which fails to link against recent lld:
#
#   ld.lld: error: section: .got is not contiguous with other relro sections
#
# fw_jump.bin is produced before that step, so tolerate the failure and check
# for the file we actually need instead of trusting the exit status.
echo "### building the OpenSBI firmware"
$CB cheri-std093-opensbi-baremetal-riscv64-purecap || \
    echo "    cheribuild reported a failure - checking whether fw_jump.bin got built anyway"

if [ ! -f "$BIOS" ]; then
    echo "ERROR: no firmware at $BIOS"
    echo "       The OpenSBI build failed before producing fw_jump.bin."
    exit 1
fi
echo "    firmware ok: $BIOS"

# ------------------------------------------------------------- copy + patch
# Patch copies, not the trees cheribuild manages, so cheribuild can still
# update the originals and you keep a working toolchain to fall back on.
mkdir -p "$CHERI_ROOT/zyseal"

if [ -d "$CHERI_ROOT/zyseal/llvm" ]; then
    echo "### $CHERI_ROOT/zyseal/llvm exists, not re-copying or re-patching"
else
    echo "### copying and patching LLVM"
    cp -a "$CHERI_ROOT/cheri-std093-llvm-project" "$CHERI_ROOT/zyseal/llvm"
    ( cd "$CHERI_ROOT/zyseal/llvm"
      patch -p1 < "$HERE/patches/02-llvm-zyseal.patch"
      patch -p1 < "$HERE/patches/03-llvm-sealed-get-fix.patch" )
fi

if [ -d "$CHERI_ROOT/zyseal/qemu" ]; then
    echo "### $CHERI_ROOT/zyseal/qemu exists, not re-copying or re-patching"
else
    echo "### copying and patching QEMU"
    cp -a "$CHERI_ROOT/cheri-std093-qemu" "$CHERI_ROOT/zyseal/qemu"
    ( cd "$CHERI_ROOT/zyseal/qemu"
      patch -p1 < "$HERE/patches/01-qemu-zyseal.patch" )
fi

# ------------------------------------------------------------- build patched
echo "### building patched LLVM"
cmake -G Ninja -S "$CHERI_ROOT/zyseal/llvm/llvm" -B "$CHERI_ROOT/zyseal/llvm-build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_PROJECTS="llvm;clang;lld" \
  -DLLVM_TARGETS_TO_BUILD="RISCV" \
  -DLLVM_ENABLE_ASSERTIONS=OFF \
  -DCMAKE_INSTALL_PREFIX="$CHERI_ROOT/zyseal/llvm-sdk"
ninja -C "$CHERI_ROOT/zyseal/llvm-build" -j"$JOBS"

echo "### building patched QEMU"
mkdir -p "$CHERI_ROOT/zyseal/qemu-build"
if [ ! -f "$CHERI_ROOT/zyseal/qemu-build/build.ninja" ]; then
    ( cd "$CHERI_ROOT/zyseal/qemu-build" && ../qemu/configure \
      --target-list=riscv64cheristd-softmmu \
      --prefix="$CHERI_ROOT/zyseal/qemu-sdk" \
      --disable-sdl --disable-gtk --disable-opengl --disable-virglrenderer \
      --disable-stack-protector --disable-strip --enable-virtfs --disable-xen \
      --disable-docs --disable-rdma --disable-werror --disable-capstone \
      --disable-bsd-user --disable-linux-user --enable-slirp=git \
      --cc=/usr/bin/cc --cxx=/usr/bin/c++ --python=/usr/bin/python3 \
      --extra-cflags=-O1 )
fi
ninja -C "$CHERI_ROOT/zyseal/qemu-build" -j"$JOBS"

echo
echo "done. now:"
echo "    cd $HERE/tests && CHERI_ROOT=$CHERI_ROOT make run"
