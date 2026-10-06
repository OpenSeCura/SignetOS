#!/usr/bin/env python3
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

"""signetfs.py - host-side tool for SignetOS disk images.

The on-disk format is the one `src/boot/fs.cpp` reads and writes, mirrored
here field for field:

  block 0      superblock (magic "SIGNETFS", version 3, geometry)
  bitmap       one bit per 4 KiB block, LSB first; sized to cover total_blocks
  inode table  128-byte inodes, sized proportionally to total_blocks at format:
               flags, nblocks, size, name[32], blocks[16], indirect, parent,
               reserved[8]
  data_start+  data blocks and single-indirect blocks; a file is up to 16
               direct blocks + 1024 indirect blocks (4,160 KiB)

Directories are inodes flagged INODE_DIR with no blocks; an inode's `parent`
is the number of the directory it is an entry of (ROOT_DIR = 0xFFFFFFFF for
`/`), so a directory's contents are found by scanning the table. There is no
ownership on the disk: after a mount every file belongs to the root
`quota_disk`, and what a holder of a derived quota can reach is decided by
the directory that quota is rooted at. `init` reads the system's own images
(`naming.bin`, `sched.bin`, `trap_mgr.bin`, `shell.bin`) out of `/`, where
nothing but the root quota is rooted; the programs the shell can `run` go in
`/bin`, which the shell reaches through a read-only quota rooted there.

  signetfs.py put <image> [--size BYTES] [--dir DIR] <file>...
      Formats `image` if it does not exist or carries no recognisable file
      system, then adds each file under its basename in directory DIR
      (default `/`; created, with its parents, if missing), replacing a file
      of the same name and leaving every other file alone -- so what the
      system wrote on earlier boots survives a rebuild.
  signetfs.py ls <image>
  signetfs.py format <image> [--size BYTES]
"""

import argparse
import os
import struct
import sys

BLOCK = 4096
MAGIC = 0x5349474E45544653  # "SIGNETFS"
VERSION = 3
BITS_PER_BLOCK = BLOCK * 8  # 32768 blocks per bitmap block (128 MiB)
DIRECT_BLOCKS = 16
INDIRECT_SLOTS = BLOCK // 4  # 1024 u32 block numbers per indirect block
MAX_FILE_BLOCKS = DIRECT_BLOCKS + INDIRECT_SLOTS
MAX_FILE_BYTES = MAX_FILE_BLOCKS * BLOCK  # 4,160 KiB
NAME_MAX = 32  # including the NUL
INODE_USED = 1
INODE_DIR = 2  # a directory: no blocks, its entries point at it
ROOT_DIR = 0xFFFFFFFF  # `parent` of an entry of `/`

# struct Superblock: u64 magic; u32 version, block_bytes; u64 total_blocks,
# data_start; u32 max_inodes, inode_table_blocks; u64 bitmap_block,
# inode_block; u32 bitmap_blocks, reserved.
SUPER = struct.Struct("<QIIQQIIQQII")
# struct Inode: u32 flags, nblocks; u64 size; char name[32]; u32 blocks[16];
# u32 indirect, parent; u8 reserved[8].
INODE = struct.Struct("<IIQ32s16III8s")
assert INODE.size == 128
INODES_PER_BLOCK = BLOCK // INODE.size
INDIRECT_FMT = struct.Struct("<%dI" % INDIRECT_SLOTS)


def default_geometry(total_blocks):
    """Computes (bitmap_block, bitmap_blocks, inode_block, inode_table_blocks,
    max_inodes, data_start) scaled to `total_blocks`."""
    bitmap_block = 1
    bitmap_blocks = (total_blocks + BITS_PER_BLOCK - 1) // BITS_PER_BLOCK
    inode_block = bitmap_block + bitmap_blocks
    # 1 inode per 64 KiB (16 blocks) of disk, at least 2 inode blocks (64 inodes).
    want_inodes = max(64, total_blocks // 16)
    inode_table_blocks = (want_inodes + INODES_PER_BLOCK - 1) // INODES_PER_BLOCK
    max_inodes = inode_table_blocks * INODES_PER_BLOCK
    data_start = inode_block + inode_table_blocks
    return (bitmap_block, bitmap_blocks, inode_block, inode_table_blocks,
            max_inodes, data_start)


def name_ok(name):
    """The rule `fs.cpp` applies to one path component: 1..NAME_MAX-1
    printable non-blank bytes, no '/', and neither "." nor ".."."""
    return (0 < len(name) < NAME_MAX and b"/" not in name and
            all(0x20 < c <= 0x7E for c in name) and name not in (b".", b".."))


class Inode:
    def __init__(self, raw=None):
        if raw is None:
            self.flags, self.nblocks, self.size = 0, 0, 0
            self.name, self.blocks = b"", [0] * DIRECT_BLOCKS
            self.indirect, self.parent = 0, 0
            return
        flags, nblocks, size, name, *rest = INODE.unpack(raw)
        self.flags, self.nblocks, self.size = flags, nblocks, size
        self.name = name.split(b"\0", 1)[0]
        self.blocks = list(rest[:DIRECT_BLOCKS])
        self.indirect = rest[DIRECT_BLOCKS]
        self.parent = rest[DIRECT_BLOCKS + 1]

    @property
    def used(self):
        return self.flags & INODE_USED != 0

    @property
    def is_dir(self):
        return self.flags & INODE_DIR != 0

    def pack(self):
        return INODE.pack(self.flags, self.nblocks, self.size,
                          self.name.ljust(NAME_MAX, b"\0"), *self.blocks,
                          self.indirect, self.parent, b"\0" * 8)


class Disk:
    """One image file; metadata is read on open and written back by save()."""

    def __init__(self, f):
        self.f = f
        f.seek(0)
        sb = f.read(BLOCK)
        if len(sb) < SUPER.size:
            raise ValueError("no superblock")
        (magic, version, block_bytes, total_blocks, data_start, max_inodes,
         inode_table_blocks, bitmap_block, inode_block, bitmap_blocks,
         _) = SUPER.unpack_from(sb)
        f.seek(0, os.SEEK_END)
        capacity_blocks = f.tell() // BLOCK
        need_bitmap = (total_blocks + BITS_PER_BLOCK - 1) // BITS_PER_BLOCK
        if (magic != MAGIC or version != VERSION or block_bytes != BLOCK or
                bitmap_block != 1 or bitmap_blocks < need_bitmap or
                inode_block != bitmap_block + bitmap_blocks or
                inode_table_blocks == 0 or
                max_inodes != inode_table_blocks * INODES_PER_BLOCK or
                data_start != inode_block + inode_table_blocks or
                not data_start < total_blocks <= capacity_blocks):
            raise ValueError("not a SignetFS image")
        self.total_blocks = total_blocks
        self.bitmap_block = bitmap_block
        self.bitmap_blocks = bitmap_blocks
        self.inode_block = inode_block
        self.inode_table_blocks = inode_table_blocks
        self.max_inodes = max_inodes
        self.data_start = data_start
        self.bitmap = bytearray(b"".join(
            self.read_block(bitmap_block + k) for k in range(bitmap_blocks)))
        table = b"".join(self.read_block(inode_block + k)
                         for k in range(inode_table_blocks))
        self.inodes = [Inode(table[i * INODE.size:(i + 1) * INODE.size])
                       for i in range(max_inodes)]
        for b in range(data_start):
            self.bit_set(b)

    def read_block(self, b):
        self.f.seek(b * BLOCK)
        return self.f.read(BLOCK).ljust(BLOCK, b"\0")

    def write_block(self, b, data):
        assert len(data) <= BLOCK
        self.f.seek(b * BLOCK)
        self.f.write(data.ljust(BLOCK, b"\0"))

    def bit_test(self, b):
        return (self.bitmap[b >> 3] >> (b & 7)) & 1 != 0

    def bit_set(self, b):
        self.bitmap[b >> 3] |= 1 << (b & 7)

    def bit_clear(self, b):
        self.bitmap[b >> 3] &= ~(1 << (b & 7)) & 0xFF

    def find(self, parent, name):
        """The inode number of entry `name` of directory `parent`, or -1."""
        for i, ino in enumerate(self.inodes):
            if ino.used and ino.parent == parent and ino.name == name:
                return i
        return -1

    def entries(self, parent):
        return [i for i, ino in enumerate(self.inodes)
                if ino.used and ino.parent == parent]

    def free_inode(self):
        for i, ino in enumerate(self.inodes):
            if not ino.used:
                return i
        raise ValueError("inode table full")

    def mkdir_p(self, path):
        """The inode number of directory `path` (ROOT_DIR for `/`), creating
        any component that does not exist yet."""
        parent = ROOT_DIR
        for comp in path.strip(b"/").split(b"/") if path.strip(b"/") else []:
            if not name_ok(comp):
                raise ValueError("bad directory name %r" % comp)
            i = self.find(parent, comp)
            if i < 0:
                i = self.free_inode()
                ino = Inode()
                ino.flags = INODE_USED | INODE_DIR
                ino.name, ino.parent = comp, parent
                self.inodes[i] = ino
            elif not self.inodes[i].is_dir:
                raise ValueError("%s: not a directory" % comp.decode())
            parent = i
        return parent

    def unlink(self, i):
        ino = self.inodes[i]
        direct_n = min(ino.nblocks, DIRECT_BLOCKS)
        for b in ino.blocks[:direct_n]:
            self.bit_clear(b)
        if ino.nblocks > DIRECT_BLOCKS and ino.indirect != 0:
            ind = INDIRECT_FMT.unpack(self.read_block(ino.indirect))
            for b in ind[:ino.nblocks - DIRECT_BLOCKS]:
                if b != 0:
                    self.bit_clear(b)
            self.bit_clear(ino.indirect)
        self.inodes[i] = Inode()

    def alloc_blocks(self, n):
        got = []
        for b in range(self.data_start, self.total_blocks):
            if len(got) == n:
                break
            if not self.bit_test(b):
                got.append(b)
        if len(got) < n:
            raise ValueError("disk full")
        for b in got:
            self.bit_set(b)
        return got

    def put(self, parent, name, data):
        """Writes `data` as file `name` of directory `parent`, replacing a
        file of that name."""
        if not name_ok(name):
            raise ValueError("bad file name %r" % name)
        if len(data) > MAX_FILE_BYTES:
            raise ValueError("%s: %d bytes, the limit is %d" %
                             (name.decode(), len(data), MAX_FILE_BYTES))
        old = self.find(parent, name)
        if old >= 0:
            if self.inodes[old].is_dir:
                raise ValueError("%s: is a directory" % name.decode())
            self.unlink(old)
        slot = self.free_inode()
        n = (len(data) + BLOCK - 1) // BLOCK
        need_meta = 1 if n > DIRECT_BLOCKS else 0
        alloc = self.alloc_blocks(n + need_meta)
        data_blocks = alloc[:n]
        indirect_block = alloc[n] if need_meta else 0
        for k, b in enumerate(data_blocks):
            self.write_block(b, data[k * BLOCK:(k + 1) * BLOCK])
        if indirect_block:
            ind = [0] * INDIRECT_SLOTS
            ind[:n - DIRECT_BLOCKS] = data_blocks[DIRECT_BLOCKS:]
            self.write_block(indirect_block, INDIRECT_FMT.pack(*ind))
        ino = Inode()
        ino.flags = INODE_USED
        ino.nblocks, ino.size, ino.name, ino.parent = n, len(data), name, parent
        direct_n = min(n, DIRECT_BLOCKS)
        ino.blocks[:direct_n] = data_blocks[:direct_n]
        ino.indirect = indirect_block
        self.inodes[slot] = ino

    def save(self):
        for k in range(self.bitmap_blocks):
            self.write_block(self.bitmap_block + k,
                             bytes(self.bitmap[k * BLOCK:(k + 1) * BLOCK]))
        for k in range(self.inode_table_blocks):
            chunk = self.inodes[k * INODES_PER_BLOCK:(k + 1) * INODES_PER_BLOCK]
            self.write_block(self.inode_block + k,
                             b"".join(i.pack() for i in chunk))
        self.f.flush()


def format_image(path, size):
    """A blank file system over the whole image (created or truncated)."""
    with open(path, "wb") as f:
        f.truncate(size)
        total_blocks = size // BLOCK
        (bitmap_block, bitmap_blocks, inode_block, inode_table_blocks,
         max_inodes, data_start) = default_geometry(total_blocks)
        if total_blocks <= data_start:
            raise ValueError("image too small")
        f.write(SUPER.pack(MAGIC, VERSION, BLOCK, total_blocks, data_start,
                           max_inodes, inode_table_blocks, bitmap_block,
                           inode_block, bitmap_blocks, 0))
        bitmap = bytearray(bitmap_blocks * BLOCK)
        for b in range(data_start):
            bitmap[b >> 3] |= 1 << (b & 7)
        f.seek(bitmap_block * BLOCK)
        f.write(bitmap)
        f.seek(inode_block * BLOCK)
        f.write(b"\0" * (inode_table_blocks * BLOCK))


def parse_size(text):
    units = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}
    if text and text[-1].upper() in units:
        return int(text[:-1]) * units[text[-1].upper()]
    return int(text)


def open_or_format(path, size):
    """A Disk over `path`, formatted first unless it already carries one."""
    if os.path.exists(path):
        try:
            f = open(path, "r+b")
            return Disk(f)
        except ValueError:
            f.close()
            print("%s: no file system; formatting" % path, file=sys.stderr)
    format_image(path, size)
    return Disk(open(path, "r+b"))


def print_tree(disk, parent=ROOT_DIR, prefix=b"", seen=None):
    """Lists every entry under `parent`, one full path per line, directories
    first and with a trailing '/'."""
    seen = set() if seen is None else seen
    items = sorted(disk.entries(parent),
                   key=lambda i: (not disk.inodes[i].is_dir, disk.inodes[i].name))
    for i in items:
        if i in seen:  # a cycle on a damaged image; fs.cpp drops these on mount
            continue
        seen.add(i)
        ino = disk.inodes[i]
        path = prefix + ino.name
        if ino.is_dir:
            print("%-31s %7s" % ((path + b"/").decode(), "dir"))
            print_tree(disk, i, path + b"/", seen)
        else:
            print("%-31s %7d bytes %4d block(s)" %
                  (path.decode(), ino.size, ino.nblocks))


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("put", help="add or replace files")
    p.add_argument("image")
    p.add_argument("--size", default="32M",
                   help="image size when formatting (default 32M)")
    p.add_argument("--dir", default="",
                   help="directory to put the files in (default /; created "
                        "if missing)")
    p.add_argument("files", nargs="+")
    p = sub.add_parser("ls", help="list files")
    p.add_argument("image")
    p = sub.add_parser("format", help="write a blank file system")
    p.add_argument("image")
    p.add_argument("--size", default="32M")
    args = ap.parse_args(argv)

    if args.cmd == "format":
        format_image(args.image, parse_size(args.size))
        return 0
    if args.cmd == "ls":
        with open(args.image, "rb") as f:
            disk = Disk(f)
        print_tree(disk)
        return 0
    disk = open_or_format(args.image, parse_size(args.size))
    directory = args.dir.strip("/")
    parent = disk.mkdir_p(directory.encode())
    for path in args.files:
        with open(path, "rb") as f:
            data = f.read()
        disk.put(parent, os.path.basename(path).encode(), data)
        print("%s: /%s%s, %d bytes" % (args.image,
                                       directory + "/" if directory else "",
                                       os.path.basename(path), len(data)))
    disk.save()
    disk.f.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, OSError) as e:
        print("signetfs: %s" % e, file=sys.stderr)
        sys.exit(1)
