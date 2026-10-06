/*
 * Copyright 2026 Google LLC (Cherified Team)
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

#pragma once

/*
 * logo.hpp - SignetOS Signet-Ring Wax-Stamping ASCII Animation & Banner
 *
 * Shared between `kernel_main` (`src/kernel/main.cpp`) and the `logo.bin`
 * user-space application (`src/external/apps/logo.cpp`).
 */

#include <signetos/types.hpp>

namespace signetos::logo {

struct Frame {
  const char* body;
  uint64_t hold_ms;
};

inline constexpr const char* kBorder =
    "================================================================================"
    "\n";

inline constexpr Frame kFrames[] = {
    // Frame 0: Hot wax drop falling toward pool
    {"        o\x1b[K\n"
     "\x1b[K\n"
     "\x1b[K\n"
     "\x1b[K\n"
     "\x1b[K\n"
     "       .~.\x1b[K\n",
     55},
    // Frame 1: Wax drop midway down, pool forming
    {"\x1b[K\n"
     "\x1b[K\n"
     "        o\x1b[K\n"
     "\x1b[K\n"
     "      .~~~.\x1b[K\n"
     "     (~~~~~)\x1b[K\n",
     55},
    // Frame 2: Drop splashes into pool; signet ring bezel enters at top
    {"    [=======]\x1b[K\n"
     "\x1b[K\n"
     "\x1b[K\n"
     "     .  o  .\x1b[K\n"
     "      .~~~.\x1b[K\n"
     "     (~~~~~)\x1b[K\n",
     55},
    // Frame 3: Signet ring descends 1 row
    {"     \\\\___//\x1b[K\n"
     "    [=======]\x1b[K\n"
     "\x1b[K\n"
     "\x1b[K\n"
     "      .~~~.\x1b[K\n"
     "     (~~~~~)\x1b[K\n",
     55},
    // Frame 4: Signet ring descends 1 row
    {"     //   \\\\\x1b[K\n"
     "     \\\\___//\x1b[K\n"
     "    [=======]\x1b[K\n"
     "\x1b[K\n"
     "      .~~~.\x1b[K\n"
     "     (~~~~~)\x1b[K\n",
     55},
    // Frame 5: Full signet ring poised above molten wax
    {"      .---.\x1b[K\n"
     "     //   \\\\\x1b[K\n"
     "     \\\\___//\x1b[K\n"
     "    [=======]\x1b[K\n"
     "      .~~~.\x1b[K\n"
     "     (~~~~~)\x1b[K\n",
     55},
    // Frame 6: Signet ring bezel contacts molten wax
    {"\x1b[K\n"
     "      .---.\x1b[K\n"
     "     //   \\\\\x1b[K\n"
     "     \\\\___//\x1b[K\n"
     "   .[=======].\x1b[K\n"
     "    (~~~~~~~)\x1b[K\n",
     50},
    // Frame 7: Signet ring presses in; wax splashes outward
    {"\x1b[K\n"
     "\x1b[K\n"
     "      .---.\x1b[K\n"
     "  *  //   \\\\  *\x1b[K\n"
     " .   \\\\___//   .\x1b[K\n"
     "   ([=======])\x1b[K\n",
     70},
    // Frame 8: Deep press; wax molds around the signet bezel
    {"\x1b[K\n"
     "\x1b[K\n"
     "      .---.\x1b[K\n"
     "     //   \\\\\x1b[K\n"
     "    /\\\\___//\\\x1b[K\n"
     "   ([=======])\x1b[K\n",
     120},
    // Frame 9: Ring begins lifting (row 1); bottom rim of seal revealed
    {"\x1b[K\n"
     "      .---.\x1b[K\n"
     "     //   \\\\\x1b[K\n"
     "     \\\\___//\x1b[K\n"
     "    [=======]\x1b[K\n"
     "     '-----'\x1b[K\n",
     60},
    // Frame 10: Ring lifts (row 2); lower inner ring revealed
    {"      .---.\x1b[K\n"
     "     //   \\\\\x1b[K\n"
     "     \\\\___//\x1b[K\n"
     "    [=======]\x1b[K\n"
     "    \\ '---' /\x1b[K\n"
     "     '-----'\x1b[K\n",
     60},
    // Frame 11: Ring lifts (row 3); [S] signet emblem revealed!
    {"     //   \\\\\x1b[K\n"
     "     \\\\___//\x1b[K\n"
     "    [=======]\x1b[K\n"
     "   | | [S] | |\x1b[K\n"
     "    \\ '---' /\x1b[K\n"
     "     '-----'\x1b[K\n",
     60},
    // Frame 12: Ring lifts (row 4); upper inner ring revealed
    {"     \\\\___//\x1b[K\n"
     "    [=======]\x1b[K\n"
     "    / .---. \\\x1b[K\n"
     "   | | [S] | |\x1b[K\n"
     "    \\ '---' /\x1b[K\n"
     "     '-----'\x1b[K\n",
     60},
    // Frame 13: Ring bezel exits top; full wax seal revealed
    {"    [=======]\x1b[K\n"
     "     .-----.\x1b[K\n"
     "    / .---. \\\x1b[K\n"
     "   | | [S] | |\x1b[K\n"
     "    \\ '---' /\x1b[K\n"
     "     '-----'\x1b[K\n",
     65},
    // Frame 14: Seal settles into place; "Si" unfurls
    {"     .-----.       ____  _\x1b[K\n"
     "    / .---. \\     / ___|(_)\x1b[K\n"
     "   | | [S] | |    \\___ \\| |\x1b[K\n"
     "    \\ '---' /      ___) | |\x1b[K\n"
     "     '-----'      |____/|_|\x1b[K\n"
     "\x1b[K\n",
     55},
    // Frame 15: "Sign" unfurls
    {"     .-----.       ____  _\x1b[K\n"
     "    / .---. \\     / ___|(_) __ _ _ __\x1b[K\n"
     "   | | [S] | |    \\___ \\| |/ _` | '_ \\\x1b[K\n"
     "    \\ '---' /      ___) | | (_| | | | |\x1b[K\n"
     "     '-----'      |____/|_|\\__, |_| |_|\x1b[K\n"
     "                           |___/\x1b[K\n",
     55},
    // Frame 16: "Signet" unfurls
    {"     .-----.       ____  _                   _\x1b[K\n"
     "    / .---. \\     / ___|(_) __ _ _ __   ___ | |_\x1b[K\n"
     "   | | [S] | |    \\___ \\| |/ _` | '_ \\ / _ \\| __|\x1b[K\n"
     "    \\ '---' /      ___) | | (_| | | | |  __/| |_|\x1b[K\n"
     "     '-----'      |____/|_|\\__, |_| |_|\\___| \\__|\x1b[K\n"
     "                           |___/\x1b[K\n",
     55},
    // Frame 17: "SignetOS" complete
    {"     .-----.       ____  _                   _    ___  ____\x1b[K\n"
     "    / .---. \\     / ___|(_) __ _ _ __   ___ | |_ / _ \\/ ___|\x1b[K\n"
     "   | | [S] | |    \\___ \\| |/ _` | '_ \\ / _ \\| __| | | \\___ \\\x1b[K\n"
     "    \\ '---' /      ___) | | (_| | | | |  __/| |_| |_| |___) |\x1b[K\n"
     "     '-----'      |____/|_|\\__, |_| |_|\\___| \\__|\\___/|____/\x1b[K\n"
     "                           |___/\x1b[K\n",
     70},
};

inline constexpr const char* kFinalBody =
    "     .-----.       ____  _                   _    ___  ____\x1b[K\n"
    "    / .---. \\     / ___|(_) __ _ _ __   ___ | |_ / _ \\/ ___|\x1b[K\n"
    "   | | [S] | |    \\___ \\| |/ _` | '_ \\ / _ \\| __| | | \\___ \\\x1b[K\n"
    "    \\ '---' /      ___) | | (_| | | | |  __/| |_| |_| |___) |\x1b[K\n"
    "     '-----'      |____/|_|\\__, |_| |_|\\___| \\__|\\___/|____/\x1b[K\n"
    "                           |___/   v0.1  |  (c) Google Cherified Team\x1b[K\n";

template <typename PrintFn>
inline void play(PrintFn&& out, uint64_t ticks_per_ms, bool animate = true) {
  auto delay_ms = [&](uint64_t ms) {
    const uint64_t ticks = ticks_per_ms * ms;
    uint64_t start = 0;
    __asm__ volatile("rdtime %0" : "=r"(start));
    uint64_t now = start;
    while (now - start < ticks) {
      __asm__ volatile("rdtime %0" : "=r"(now));
    }
  };

  if (animate) {
    out("\x1b[?25l\n");
    out(kBorder);
    for (const Frame& f : kFrames) {
      out(f.body);
      out(kBorder);
      delay_ms(f.hold_ms);
      out("\x1b[7A\r");
    }
  } else {
    out("\n");
    out(kBorder);
  }
  out(kFinalBody);
  out(kBorder);
  if (animate) {
    out("\x1b[?25h");
  }
}

}  // namespace signetos::logo
