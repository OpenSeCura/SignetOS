 #
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
 #


#!/bin/bash
# Apply the Zyseal patches to the LLVM and QEMU trees. Fetching and building
# are ../setup.sh's job, which runs this between the two.
#
#   LLVM_SRC   LLVM tree to patch (default $CHERI_ROOT/zyseal/llvm)
#   QEMU_SRC   QEMU tree to patch (default $CHERI_ROOT/zyseal/qemu)
#
# Re-running is safe: a patch that is already applied is skipped.
set -e

CHERI_ROOT=${CHERI_ROOT:-$HOME/cheri}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LLVM_SRC=${LLVM_SRC:-$CHERI_ROOT/zyseal/llvm}
QEMU_SRC=${QEMU_SRC:-$CHERI_ROOT/zyseal/qemu}

# apply TREE PATCH: patch TREE, unless PATCH reverses cleanly (already in).
apply() {
    if [ ! -d "$1" ]; then
        echo "ERROR: no tree at $1 (run ../setup.sh)"
        exit 1
    fi
    if ( cd "$1" && patch -p1 -R -s -f --dry-run < "$2" ) > /dev/null 2>&1; then
        echo "### $(basename "$2") already applied"
    else
        echo "### applying $(basename "$2")"
        ( cd "$1" && patch -p1 < "$2" )
    fi
}

apply "$QEMU_SRC" "$HERE/patches/01-qemu-zyseal.patch"
apply "$LLVM_SRC" "$HERE/patches/02-llvm-zyseal.patch"
apply "$LLVM_SRC" "$HERE/patches/03-llvm-sealed-get-fix.patch"
