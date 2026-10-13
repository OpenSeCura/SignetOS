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
# Apply the mmodemmu patches to the QEMU tree, on top of Zyseal's. Fetching
# and building are ../setup.sh's job, which runs this between the two.
#
#   QEMU_SRC   QEMU tree to patch (default $CHERI_ROOT/zyseal/qemu)
#
# Re-running is safe: a patch that is already applied is skipped.
set -e

CHERI_ROOT=${CHERI_ROOT:-$HOME/cheri}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
QEMU_SRC=${QEMU_SRC:-$CHERI_ROOT/zyseal/qemu}

if [ ! -d "$QEMU_SRC" ]; then
    echo "ERROR: no QEMU tree at $QEMU_SRC (run ../setup.sh)"
    exit 1
fi

# A patch that reverses cleanly is taken as already applied.
for p in "$HERE"/patches/*-qemu-*.patch; do
    [ -f "$p" ] || continue
    if ( cd "$QEMU_SRC" && patch -p1 -R -s -f --dry-run < "$p" ) > /dev/null 2>&1; then
        echo "### $(basename "$p") already applied"
    else
        echo "### applying $(basename "$p")"
        ( cd "$QEMU_SRC" && patch -p1 < "$p" )
    fi
done
