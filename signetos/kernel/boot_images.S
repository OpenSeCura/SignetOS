/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * boot_images.S - Embedded User-Space Compartment Binaries
 *
 * Packages the standalone boot compartment binaries (`boot/<name>.bin`,
 * all linked with `user/compartment.ld`) into the kernel's `.rodata` section.
 *
 * Each image starts on a 4 KiB boundary and is zero-padded to a whole number
 * of pages, and its `.size` covers the padding. The kernel reaches an image
 * through the capability the linker's `__cap_relocs` entry describes with
 * exactly that base and size, and a capability's bounds are only exact when
 * base and top are aligned to a power of two that grows with the length (a
 * 35 KiB object needs 128-byte alignment). With merely 16-byte alignment the
 * hardware rounds the base down and the top up while the cursor stays at the
 * symbol, so `capability_get_length()` exceeds the image and
 * `init::image_install` reads past it. Page alignment at both ends keeps
 * every image capability exact for images far larger than any here;
 * `init::image_header` rejects an image whose cursor is not its base.
 *
 * At boot, `init::launch()` loads `_boot_img_init` into the `init` compartment
 * and hands `init` read-only capabilities to the remaining packaged images
 * via `BootManifest`.
 *
 * Only `boot/` is packaged here: `init` and what it needs to reach the
 * disk (`uart` to report, `loader` to load, `blk` and `fs` to read). Every
 * external service (`external/services/` -- `naming`, `sched`, `trap_mgr`,
 * `shell`) and program (`external/apps/`) is a file on the disk image
 * (`tools/signetfs.py` puts them there at build time) that `init` or the
 * shell reads through `fs` and loads through `loader`.
 */

    .section .rodata.boot_images, "a", @progbits

.macro BOOT_IMAGE name, path
    .p2align 12
    .globl _boot_img_\name
    .type _boot_img_\name, @object
_boot_img_\name:
    .incbin "\path"
    .p2align 12
.L_boot_img_\name\()_end:
    .size _boot_img_\name, .L_boot_img_\name\()_end - _boot_img_\name
.endm

BOOT_IMAGE init,     "boot/init.bin"
BOOT_IMAGE uart,     "boot/uart.bin"
BOOT_IMAGE blk,      "boot/blk.bin"
BOOT_IMAGE loader,   "boot/loader.bin"
BOOT_IMAGE fs,       "boot/fs.bin"
