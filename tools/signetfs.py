#!/usr/bin/env python3
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

"""signetfs.py - host-side tool for SignetOS disk images.

The on-disk format is the one `boot/fs.cpp` reads and writes:

  block 0      header: magic "SIGCAPFS", version 2, total_blocks
  1..          entry table, one 128-byte entry per disk block: flags, parent,
               payer, generation, size, block_count, tree, the name (length,
               hash, tree, head[20]), blocks[16]
  data_start+  data blocks, and the blocks and lists of trees

A file's first 16 blocks are listed in its entry and the rest are a tree
(`tree`). A name of up to 20 bytes is all in its entry's `head`; a longer one
is all in a tree of its own, with its first 20 bytes in `head` as well. A
tree of one block is just that block; a bigger one hangs from lists of 1024
block numbers, as many levels of them as its block count needs. So neither
files nor names have a size limit but the disk.

Entry 0 is `/`, entry 1 the root quota. `parent` is the containing directory
(for a quota, the quota it was made from); `payer` is the quota that pays for
an entry. Free blocks are not stored; they follow from the entries. For a
quota, `blocks` holds what it pays for (`used`, a u64); for a link (flag 16),
the entry it names, that entry's generation, and rights. This tool leaves
`used` alone: the file system counts it again at mount.

  signetfs.py put <image> [--size BYTES] [--dir DIR] [--keep] <file>...
      Formats `image` if it does not exist or carries no recognisable file
      system, then adds each file under its basename in directory DIR
      (default `/`; created, with its parents, if missing), replacing a file
      of the same name and leaving every other file alone -- so what the
      system wrote on earlier boots survives a rebuild. --keep does not
      replace existing files.
  signetfs.py ls <image>
  signetfs.py format <image> [--size BYTES]
  signetfs.py swap <image> --size BYTES
      Gives `image` a swap region of BYTES (0: none) after its file system,
      and a last sector describing it -- magic "SIGNSWAP", version, sector
      size, first sector, sectors -- which `blk` reads (user/abi.hpp,
      SwapTrailer): the kernel pages memory out there. The region is sparse,
      and whatever it held before is dropped.
"""

import argparse
import os
import struct
import sys

BLOCK = 4096
MAGIC = 0x5349474341504653  # "SIGCAPFS"
VERSION = 2
DIRECT_BLOCKS = 16
NAME_HEAD = 20  # bytes of a name kept in its entry (FS_NAME_INLINE)
FANOUT = BLOCK // 4  # block numbers per list block
IN_USE, DIR, QUOTA = 1, 2, 4
NO_ENTRY = 0xFFFFFFFF  # no entry
ROOT_DIR, ROOT_QUOTA = 0, 1

# struct DiskHeader: u64 magic, version, total_blocks.
DISK_HEADER = struct.Struct("<QQQ")
# struct Entry: u32 flags, parent, payer, generation; u64 size; u32
# block_count, tree; struct Name { u32 length, hash, tree; char head[20]; };
# u32 blocks[16].
ENTRY = struct.Struct("<IIIIQIIIII%ds16I" % NAME_HEAD)
assert ENTRY.size == 128
ENTRIES_PER_BLOCK = BLOCK // ENTRY.size
LIST = struct.Struct("<%dI" % FANOUT)

# The last sector of an image with a swap region: u64 magic; u32 version,
# sector_bytes; u64 base_sector, sectors (user/abi.hpp, SwapTrailer).
SECTOR = 512
SWAP_MAGIC = 0x5349474E53574150  # "SIGNSWAP"
SWAP_VERSION = 1
SWAP_TRAILER = struct.Struct("<QIIQQ")


def geometry(total_blocks):
    """(entry_count, data_start): one entry per block, table from block 1."""
    entry_count = -(-total_blocks // ENTRIES_PER_BLOCK) * ENTRIES_PER_BLOCK
    return entry_count, 1 + entry_count // ENTRIES_PER_BLOCK


def name_ok(name):
    """The rule `fs.cpp` applies to one path component: one or more
    printable non-blank bytes, no '/', and neither "." nor ".."."""
    return (len(name) > 0 and b"/" not in name and
            all(0x20 < c <= 0x7E for c in name) and name not in (b".", b".."))


def name_hash(name):
    """FNV-1a, as `fs.cpp` hashes a name."""
    h = 2166136261
    for c in name:
        h = ((h ^ c) * 16777619) & 0xFFFFFFFF
    return h


def name_blocks(length):
    """Blocks of a name of `length` bytes; none if it fits in its entry."""
    return 0 if length <= NAME_HEAD else -(-length // BLOCK)


def levels(count):
    """Levels of lists in a tree of `count` blocks."""
    depth, span = 0, 1
    while span < count:
        depth, span = depth + 1, span * FANOUT
    return depth


class Entry:
    def __init__(self, raw=None):
        fields = ENTRY.unpack(raw or bytes(ENTRY.size))
        (self.flags, self.parent, self.payer, self.generation, self.size,
         self.block_count, self.tree, self.name_length, _hash,
         self.name_tree, head) = fields[:11]
        self.blocks = list(fields[11:])
        # The whole name; a long one is read in by Disk.
        self.name = head[:min(self.name_length, NAME_HEAD)]

    in_use = property(lambda self: self.flags & IN_USE != 0)
    is_dir = property(lambda self: self.flags & DIR != 0)
    is_quota = property(lambda self: self.flags & QUOTA != 0)

    def pack(self):
        return ENTRY.pack(self.flags, self.parent, self.payer,
                          self.generation, self.size, self.block_count,
                          self.tree, len(self.name), name_hash(self.name),
                          self.name_tree,
                          self.name[:NAME_HEAD].ljust(NAME_HEAD, b"\0"),
                          *self.blocks)


class Disk:
    """One image file; metadata is read on open and written back by save()."""

    def __init__(self, f):
        self.f = f
        f.seek(0)
        header = f.read(BLOCK)
        if len(header) < DISK_HEADER.size:
            raise ValueError("no header")
        magic, version, total_blocks = DISK_HEADER.unpack_from(header)
        f.seek(0, os.SEEK_END)
        capacity_blocks = f.tell() // BLOCK
        entry_count, data_start = geometry(total_blocks)
        if (magic != MAGIC or version != VERSION or
                not data_start < total_blocks <= capacity_blocks):
            raise ValueError("not a SignetFS image")
        self.total_blocks, self.data_start = total_blocks, data_start
        table = b"".join(self.read_block(1 + k)
                         for k in range(entry_count // ENTRIES_PER_BLOCK))
        self.entries = [Entry(table[i * ENTRY.size:(i + 1) * ENTRY.size])
                        for i in range(entry_count)]
        self.blocks_in_use = set(range(data_start))
        for entry in self.entries:
            if entry.in_use and entry.name_length > NAME_HEAD:
                data, _ = self.tree_blocks(entry.name_tree,
                                           name_blocks(entry.name_length))
                entry.name = b"".join(self.read_block(b) for b in data)[
                    :entry.name_length]
            if entry.in_use:
                self.blocks_in_use.update(self.blocks_of(entry))

    def read_block(self, b):
        self.f.seek(b * BLOCK)
        return self.f.read(BLOCK).ljust(BLOCK, b"\0")

    def write_block(self, b, data):
        assert len(data) <= BLOCK
        self.f.seek(b * BLOCK)
        self.f.write(data.ljust(BLOCK, b"\0"))

    def tree_blocks(self, root, count):
        """(blocks, lists) of the tree `root` of `count` blocks."""
        if count == 0:
            return [], []
        nodes, lists = [root], []
        for level in reversed(range(levels(count))):
            lists += nodes
            children = []
            for node in nodes:
                children += LIST.unpack(self.read_block(node))
            nodes = children[:-(-count // FANOUT ** level)]
        return nodes, lists

    def make_tree(self, blocks):
        """The root of a new tree of `blocks`, its lists allocated and
        written: the tree `fs.cpp` builds by adding them one at a time."""
        nodes = list(blocks)
        while len(nodes) > 1:
            lists = self.alloc_blocks(-(-len(nodes) // FANOUT))
            for k, block in enumerate(lists):
                chunk = nodes[k * FANOUT:(k + 1) * FANOUT]
                self.write_block(block, LIST.pack(
                    *(chunk + [0] * (FANOUT - len(chunk)))))
            nodes = lists
        return nodes[0] if nodes else 0

    def blocks_of(self, entry):
        """Every block `entry` holds: a file's, its lists, and its name's."""
        held = entry.blocks[:min(entry.block_count, DIRECT_BLOCKS)]
        if entry.block_count > DIRECT_BLOCKS:
            data, lists = self.tree_blocks(entry.tree,
                                           entry.block_count - DIRECT_BLOCKS)
            held = held + data + lists
        if entry.name_length > NAME_HEAD:
            data, lists = self.tree_blocks(entry.name_tree,
                                           name_blocks(entry.name_length))
            held = held + data + lists
        return held

    def find(self, parent, name):
        """The number of entry `name` of directory `parent`, or -1."""
        for i, entry in enumerate(self.entries):
            if entry.in_use and entry.parent == parent and entry.name == name:
                return i
        return -1

    def children(self, parent):
        return [i for i, entry in enumerate(self.entries)
                if entry.in_use and entry.parent == parent and i > ROOT_QUOTA]

    def unused_entry(self):
        for i, entry in enumerate(self.entries):
            if i > ROOT_QUOTA and not entry.in_use:
                return i
        raise ValueError("entry table full")

    def new_entry(self, flags, parent, name, payer=ROOT_QUOTA, size=0):
        """A new entry, its name's blocks (for a long one) written."""
        entry = Entry()
        entry.flags, entry.parent, entry.name = IN_USE | flags, parent, name
        entry.payer, entry.size = payer, size
        entry.name_length = len(name)
        if len(name) > NAME_HEAD:
            blocks = self.alloc_blocks(name_blocks(len(name)))
            for k, block in enumerate(blocks):
                self.write_block(block, name[k * BLOCK:(k + 1) * BLOCK])
            entry.name_tree = self.make_tree(blocks)
        return entry

    def mkdir_p(self, path):
        """The entry number of directory `path` (ROOT_DIR for `/`), creating
        any component that does not exist yet."""
        parent = ROOT_DIR
        for comp in path.strip(b"/").split(b"/") if path.strip(b"/") else []:
            if not name_ok(comp):
                raise ValueError("bad directory name %r" % comp)
            i = self.find(parent, comp)
            if i < 0:
                i = self.unused_entry()
                self.entries[i] = self.new_entry(DIR, parent, comp)
            elif not self.entries[i].is_dir:
                raise ValueError("%s: not a directory" % comp.decode())
            parent = i
        return parent

    def unlink(self, i):
        self.blocks_in_use.difference_update(self.blocks_of(self.entries[i]))
        self.entries[i] = Entry()

    def alloc_blocks(self, count):
        blocks = []
        for block in range(self.data_start, self.total_blocks):
            if len(blocks) == count:
                break
            if block not in self.blocks_in_use:
                blocks.append(block)
        if len(blocks) < count:
            raise ValueError("disk full")
        self.blocks_in_use.update(blocks)
        return blocks

    def put(self, parent, name, data):
        """Writes `data` as file `name` of directory `parent`, replacing a
        file of that name."""
        if not name_ok(name):
            raise ValueError("bad file name %r" % name)
        old = self.find(parent, name)
        if old >= 0:
            if self.entries[old].is_dir:
                raise ValueError("%s: is a directory" % name.decode())
            self.unlink(old)
        slot = self.unused_entry()
        count = -(-len(data) // BLOCK)
        blocks = self.alloc_blocks(count)
        for k, block in enumerate(blocks):
            self.write_block(block, data[k * BLOCK:(k + 1) * BLOCK])
        entry = self.new_entry(0, parent, name, size=len(data))
        entry.block_count = count
        entry.blocks[:min(count, DIRECT_BLOCKS)] = blocks[:DIRECT_BLOCKS]
        if count > DIRECT_BLOCKS:
            entry.tree = self.make_tree(blocks[DIRECT_BLOCKS:])
        self.entries[slot] = entry

    def save(self):
        for k in range(len(self.entries) // ENTRIES_PER_BLOCK):
            chunk = self.entries[k * ENTRIES_PER_BLOCK:(k + 1) * ENTRIES_PER_BLOCK]
            self.write_block(1 + k, b"".join(entry.pack() for entry in chunk))
        self.f.flush()


def format_image(path, size):
    """A blank file system over the whole image (created or truncated)."""
    total_blocks = size // BLOCK
    entry_count, data_start = geometry(total_blocks)
    if total_blocks <= data_start:
        raise ValueError("image too small")
    table = [Entry() for _ in range(entry_count)]
    for i, flags, payer in ((ROOT_DIR, DIR, ROOT_QUOTA),
                            (ROOT_QUOTA, QUOTA, NO_ENTRY)):
        table[i].flags, table[i].parent, table[i].payer = (
            IN_USE | flags, NO_ENTRY, payer)
    table[ROOT_QUOTA].size = (total_blocks - data_start) * BLOCK
    with open(path, "wb") as f:
        f.truncate(size)
        f.write(DISK_HEADER.pack(MAGIC, VERSION, total_blocks))
        f.seek(BLOCK)
        f.write(b"".join(entry.pack() for entry in table))


def set_swap(path, size):
    """Gives the image at `path` a swap region of `size` bytes, in whole
    pages, between its file system and a last sector describing it; for 0,
    none. The file system is left as it is."""
    with open(path, "r+b") as f:
        fs_bytes = Disk(f).total_blocks * BLOCK
        size -= size % BLOCK
        f.truncate(fs_bytes)  # any old region, and its sector, go
        if size > 0:
            f.truncate(fs_bytes + size + SECTOR)
            f.seek(fs_bytes + size)
            f.write(SWAP_TRAILER.pack(SWAP_MAGIC, SWAP_VERSION, SECTOR,
                                      fs_bytes // SECTOR, size // SECTOR))


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
    first and with a trailing '/'; quotas prefixed `quota:`."""
    seen = set() if seen is None else seen
    items = sorted(disk.children(parent),
                   key=lambda i: (not disk.entries[i].is_dir, disk.entries[i].name))
    for i in items:
        if i in seen:  # a cycle on a damaged image; fs.cpp drops these on mount
            continue
        seen.add(i)
        entry = disk.entries[i]
        path = prefix + entry.name
        if entry.is_quota:
            print("%-31s %7d bytes" % ((b"quota:" + path).decode(), entry.size))
            print_tree(disk, i, path + b"/", seen)
        elif entry.is_dir:
            print("%-31s %7s" % ((path + b"/").decode(), "dir"))
            print_tree(disk, i, path + b"/", seen)
        else:
            print("%-31s %7d bytes %4d block(s)" %
                  (path.decode(), entry.size, entry.block_count))
    if parent == ROOT_DIR:
        print_tree(disk, ROOT_QUOTA, b"", seen)


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
    p.add_argument("--keep", action="store_true",
                   help="leave a file that is there already as it is")
    p.add_argument("files", nargs="+")
    p = sub.add_parser("ls", help="list files and quotas")
    p.add_argument("image")
    p = sub.add_parser("format", help="write a blank file system")
    p.add_argument("image")
    p.add_argument("--size", default="32M")
    p = sub.add_parser("swap", help="give the image a swap region")
    p.add_argument("image")
    p.add_argument("--size", required=True, help="bytes of swap; 0 for none")
    args = ap.parse_args(argv)

    if args.cmd == "swap":
        size = parse_size(args.size)
        set_swap(args.image, size)
        print("%s: %s" % (args.image, "%d KiB of swap" % (size // 1024)
                          if size >= BLOCK else "no swap"))
        return 0

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
        name = os.path.basename(path).encode()
        if args.keep and disk.find(parent, name) >= 0:
            continue
        with open(path, "rb") as f:
            data = f.read()
        disk.put(parent, name, data)
        print("%s: /%s%s, %d bytes" % (args.image,
                                       directory + "/" if directory else "",
                                       name.decode(), len(data)))
    disk.save()
    disk.f.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, OSError) as e:
        print("signetfs: %s" % e, file=sys.stderr)
        sys.exit(1)
