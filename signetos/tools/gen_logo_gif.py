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

"""
gen_logo_gif.py - Generates signetos/assets/signetos_logo.gif from logo.hpp
using PyCairo and ImageMagick. Renders ANSI-colored frames directly on a dark
terminal background with the typewriter cursor, without window card chrome.
"""

import codecs
import os
import re
import subprocess
import tempfile
import cairo

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOGO_HPP = os.path.join(REPO_ROOT, "include", "signetos", "logo.hpp")
OUTPUT_GIF = os.path.join(REPO_ROOT, "assets", "signetos_logo.gif")

# Color palette
C_BG = (0x0d / 255, 0x11 / 255, 0x17 / 255)         # Dark terminal background
C_BORDER = (0x38 / 255, 0x3f / 255, 0x47 / 255)     # Subtle slate for border '=' lines
C_DEFAULT_TEXT = (0xf0 / 255, 0xf6 / 255, 0xfc / 255)

ANSI_MAP = {
    '91': (0xf8 / 255, 0x51 / 255, 0x49 / 255),     # Red (wax drop, pool, seal outline)
    '93': (0xe3 / 255, 0xb3 / 255, 0x41 / 255),     # Gold (signet ring, sparks, [S] emblem)
    '97': (0xf0 / 255, 0xf6 / 255, 0xfc / 255),     # White (SignetOS lettering, cursor)
    '90': (0x8b / 255, 0x94 / 255, 0x9e / 255),     # Gray (copyright metadata)
}

def parse_line_ansi(line, is_border=False):
    """Parses a string containing ANSI escape sequences into (char, rgb_color) tuples."""
    parts = re.split(r'(\x1b\[[0-9;]*[a-zA-Z])', line)
    color = C_BORDER if is_border else C_DEFAULT_TEXT
    chars = []
    for part in parts:
        if not part:
            continue
        if part.startswith('\x1b['):
            code = part[2:-1]
            if code in ('0', ''):
                color = C_DEFAULT_TEXT
            elif is_border and code == '90':
                color = C_BORDER
            elif code in ANSI_MAP:
                color = ANSI_MAP[code]
        else:
            for ch in part:
                chars.append((ch, color))
    return chars

def main():
    with open(LOGO_HPP, "r", encoding="utf-8") as f:
        content = f.read()

    # Expand ANSI macros to literal escape sequences
    macros = {
        "ANSI_RESET": "\x1b[0m",
        "ANSI_RED": "\x1b[91m",
        "ANSI_GOLD": "\x1b[93m",
        "ANSI_WHITE": "\x1b[97m",
        "ANSI_GRAY": "\x1b[90m",
    }
    for name, val in macros.items():
        content = content.replace(name, f'"{val}"')

    frames_block = re.search(r'kFrames\[\] = \{(.*?)\};', content, re.DOTALL).group(1)
    entries = re.findall(r'\{\s*((?:"(?:[^"\\]|\\.)*"\s*)+),\s*(\d+)\s*\}', frames_block)

    delays = [int(ms) for _, ms in entries]
    delays.append(2500)  # Hold final completed frame for 2.5s

    frames = []
    for str_block, _ in entries:
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', str_block)
        raw_bytes = "".join(parts).encode("utf-8")
        decoded = codecs.escape_decode(raw_bytes)[0].decode("utf-8").replace("\x1b[K", "")
        flines = decoded.splitlines()
        # Omit v0.1 in the README GIF while keeping copyright aligned
        for i in range(len(flines)):
            flines[i] = flines[i].replace("v0.1  |  ", "         ")
        frames.append(flines)

    final_match = re.search(r'kFinalBody =\s*((?:"(?:[^"\\]|\\.)*"\s*)+);', content)
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', final_match.group(1))
    raw_bytes = "".join(parts).encode("utf-8")
    final_decoded = codecs.escape_decode(raw_bytes)[0].decode("utf-8").replace("\x1b[K", "")
    final_lines = final_decoded.splitlines()

    # Omit v0.1 in the README GIF while keeping copyright aligned
    if final_lines:
        for i in range(len(final_lines)):
            final_lines[i] = final_lines[i].replace("v0.1  |  ", "         ")
    frames.append(final_lines)

    os.makedirs(os.path.dirname(OUTPUT_GIF), exist_ok=True)

    char_w = 8.0
    line_h = 19.0
    pad_x = 24.0
    pad_y = 16.0
    total_w = int(round(pad_x * 2 + 80 * char_w))  # 688 px
    total_h = int(round(pad_y * 2 + 8 * line_h))    # 184 px

    border_line = "=" * 80

    with tempfile.TemporaryDirectory() as tmpdir:
        for f_idx, flines in enumerate(frames):
            while len(flines) < 6:
                flines.append("")
            all_raw_lines = [border_line] + flines[:6] + [border_line]

            surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, total_w * 2, total_h * 2)
            ctx = cairo.Context(surface)
            ctx.scale(2.0, 2.0)

            # Clean terminal background (no window frame or buttons)
            ctx.set_source_rgb(*C_BG)
            ctx.paint()

            # Monospace text rendering
            ctx.select_font_face("DejaVu Sans Mono", cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_NORMAL)
            ctx.set_font_size(13.0)

            for r_idx, raw_line in enumerate(all_raw_lines):
                is_b = (r_idx == 0 or r_idx == 7)
                chars = parse_line_ansi(raw_line, is_border=is_b)
                y = pad_y + r_idx * line_h + 14.0
                for c_idx, (ch, color) in enumerate(chars):
                    if ch == ' ':
                        continue
                    x = pad_x + c_idx * char_w
                    ctx.set_source_rgb(*color)
                    ctx.move_to(x, y)
                    ctx.show_text(ch)

            png_path = os.path.join(tmpdir, f"frame_{f_idx:02d}.png")
            surface.write_to_png(png_path)

        # Assemble GIF
        raw_gif = os.path.join(tmpdir, "raw.gif")
        cmd = ["convert", "-loop", "0"]
        for f_idx, ms in enumerate(delays):
            cs = max(1, round(ms / 10.0))
            cmd.extend(["-delay", str(cs), os.path.join(tmpdir, f"frame_{f_idx:02d}.png")])
        cmd.append(raw_gif)
        subprocess.run(cmd, check=True)

        # Optimize GIF layers & palette
        subprocess.run(["convert", raw_gif, "-layers", "Optimize", OUTPUT_GIF], check=True)
        print(f"Generated {OUTPUT_GIF} ({os.path.getsize(OUTPUT_GIF)} bytes)")

if __name__ == "__main__":
    main()
