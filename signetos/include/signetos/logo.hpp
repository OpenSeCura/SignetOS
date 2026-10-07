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

#pragma once

/*
 * logo.hpp - SignetOS Signet-Ring Wax-Stamping ASCII Animation & Banner
 *
 * Shared between `kernel_main` (`kernel/main.cpp`) and the `logo.bin`
 * user-space application (`external/apps/logo.cpp`).
 */

#include <signetos/types.hpp>

namespace signetos::logo {

#define ANSI_RESET  "\x1b[0m"
#define ANSI_RED    "\x1b[91m"
#define ANSI_GOLD   "\x1b[93m"
#define ANSI_WHITE  "\x1b[97m"
#define ANSI_GRAY   "\x1b[90m"

struct Frame {
  const char* body;
  uint64_t hold_ms;
};

inline constexpr const char* kBorder =
    ANSI_GRAY
    "================================================================================"
    ANSI_RESET "\n";

inline constexpr Frame kFrames[] = {
    // Frame 0: Hot wax drop falling toward pool
    {"        " ANSI_RED "o" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n"
     "\x1b[K\n"
     "\x1b[K\n"
     "       " ANSI_RED ".~." ANSI_RESET "\x1b[K\n"
     "\x1b[K\n",
     55},
    // Frame 1: Wax drop midway down, pool forming
    {"\x1b[K\n"
     "        " ANSI_RED "o" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n"
     "      " ANSI_RED ".~~~." ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "(~~~~~)" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n",
     55},
    // Frame 2: Drop splashes into pool; signet ring bezel enters at top
    {"    " ANSI_GOLD "[=======]" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n"
     "     " ANSI_RED ".  o  ." ANSI_RESET "\x1b[K\n"
     "      " ANSI_RED ".~~~." ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "(~~~~~)" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n",
     55},
    // Frame 3: Signet ring descends 1 row
    {"     " ANSI_GOLD "\\\\___//" ANSI_RESET "\x1b[K\n"
     "    " ANSI_GOLD "[=======]" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n"
     "      " ANSI_RED ".~~~." ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "(~~~~~)" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n",
     55},
    // Frame 4: Signet ring descends 1 row
    {"     " ANSI_GOLD "//   \\\\" ANSI_RESET "\x1b[K\n"
     "     " ANSI_GOLD "\\\\___//" ANSI_RESET "\x1b[K\n"
     "    " ANSI_GOLD "[=======]" ANSI_RESET "\x1b[K\n"
     "      " ANSI_RED ".~~~." ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "(~~~~~)" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n",
     55},
    // Frame 5: Full signet ring poised above molten wax
    {"      " ANSI_GOLD ".---." ANSI_RESET "\x1b[K\n"
     "     " ANSI_GOLD "//   \\\\" ANSI_RESET "\x1b[K\n"
     "     " ANSI_GOLD "\\\\___//" ANSI_RESET "\x1b[K\n"
     "    " ANSI_GOLD "[=======]" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "(~~~~~)" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n",
     55},
    // Frame 6: Signet ring bezel contacts molten wax
    {"      " ANSI_GOLD ".---." ANSI_RESET "\x1b[K\n"
     "     " ANSI_GOLD "//   \\\\" ANSI_RESET "\x1b[K\n"
     "     " ANSI_GOLD "\\\\___//" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "." ANSI_GOLD "[=======]" ANSI_RED "." ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "(~~~~~~~)" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n",
     50},
    // Frame 7: Signet ring presses in; wax splashes outward
    {"\x1b[K\n"
     "      " ANSI_GOLD ".---." ANSI_RESET "\x1b[K\n"
     "  " ANSI_GOLD "*  //   \\\\  *" ANSI_RESET "\x1b[K\n"
     " " ANSI_GOLD ".   \\\\___//   ." ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "(" ANSI_GOLD "[=======]" ANSI_RED ")" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n",
     70},
    // Frame 8: Deep press; wax molds around the signet bezel
    {"\x1b[K\n"
     "      " ANSI_GOLD ".---." ANSI_RESET "\x1b[K\n"
     "     " ANSI_GOLD "//   \\\\" ANSI_RESET "\x1b[K\n"
     "    " ANSI_GOLD "/\\\\___//\\" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "(" ANSI_GOLD "[=======]" ANSI_RED ")" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n",
     120},
    // Frame 9: Ring begins lifting (row 1); bottom rim of seal revealed
    {"      " ANSI_GOLD ".---." ANSI_RESET "\x1b[K\n"
     "     " ANSI_GOLD "//   \\\\" ANSI_RESET "\x1b[K\n"
     "     " ANSI_GOLD "\\\\___//" ANSI_RESET "\x1b[K\n"
     "    " ANSI_GOLD "[=======]" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n",
     60},
    // Frame 10: Ring lifts (row 2); lower inner ring revealed
    {"     " ANSI_GOLD "//   \\\\" ANSI_RESET "\x1b[K\n"
     "     " ANSI_GOLD "\\\\___//" ANSI_RESET "\x1b[K\n"
     "    " ANSI_GOLD "[=======]" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n",
     60},
    // Frame 11: Ring lifts (row 3); [S] signet emblem revealed!
    {"     " ANSI_GOLD "\\\\___//" ANSI_RESET "\x1b[K\n"
     "    " ANSI_GOLD "[=======]" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n",
     60},
    // Frame 12: Ring lifts (row 4); upper inner ring revealed
    {"    " ANSI_GOLD "[=======]" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "/ .---. \\" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n",
     60},
    // Frame 13: Ring bezel exits top; full wax seal revealed
    {"     " ANSI_RED ".-----." ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "/ .---. \\" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n",
     65},
    // Frame 14: Seal settles into place; "Si" unfurls
    {"     " ANSI_RED ".-----." ANSI_RESET "       " ANSI_WHITE "____  _" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "/ .---. \\" ANSI_RESET "     " ANSI_WHITE "/ ___|(_)" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "    " ANSI_WHITE "\\___ \\| |" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "      " ANSI_WHITE "___) | |" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "      " ANSI_WHITE "|____/|_|" ANSI_RESET "\x1b[K\n"
     "\x1b[K\n",
     60},
    // Frame 15: "Sign" unfurls
    {"     " ANSI_RED ".-----." ANSI_RESET "       " ANSI_WHITE "____  _" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "/ .---. \\" ANSI_RESET "     " ANSI_WHITE "/ ___|(_) __ _ _ __" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "    " ANSI_WHITE "\\___ \\| |/ _` | '_ \\" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "      " ANSI_WHITE "___) | | (_| | | | |" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "      " ANSI_WHITE "|____/|_|\\__, |_| |_|" ANSI_RESET "\x1b[K\n"
     "                           " ANSI_WHITE "|___/" ANSI_RESET "\x1b[K\n",
     60},
    // Frame 16: "Signet" unfurls
    {"     " ANSI_RED ".-----." ANSI_RESET "       " ANSI_WHITE "____  _                   _" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "/ .---. \\" ANSI_RESET "     " ANSI_WHITE "/ ___|(_) __ _ _ __   ___ | |_" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "    " ANSI_WHITE "\\___ \\| |/ _` | '_ \\ / _ \\| __|" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "      " ANSI_WHITE "___) | | (_| | | | |  __/| |_|" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "      " ANSI_WHITE "|____/|_|\\__, |_| |_|\\___| \\__|" ANSI_RESET "\x1b[K\n"
     "                           " ANSI_WHITE "|___/" ANSI_RESET "\x1b[K\n",
     60},
    // Frame 17: "SignetOS" complete
    {"     " ANSI_RED ".-----." ANSI_RESET "       " ANSI_WHITE "____  _                   _    ___  ____" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "/ .---. \\" ANSI_RESET "     " ANSI_WHITE "/ ___|(_) __ _ _ __   ___ | |_ / _ \\/ ___|" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "    " ANSI_WHITE "\\___ \\| |/ _` | '_ \\ / _ \\| __| | | \\___ \\" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "      " ANSI_WHITE "___) | | (_| | | | |  __/| |_| |_| |___) |" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "      " ANSI_WHITE "|____/|_|\\__, |_| |_|\\___| \\__|\\___/|____/" ANSI_RESET "\x1b[K\n"
     "                           " ANSI_WHITE "|___/" ANSI_RESET "\x1b[K\n",
     140},
    // Frame 18: Cursor blinks on underneath text
    {"     " ANSI_RED ".-----." ANSI_RESET "       " ANSI_WHITE "____  _                   _    ___  ____" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "/ .---. \\" ANSI_RESET "     " ANSI_WHITE "/ ___|(_) __ _ _ __   ___ | |_ / _ \\/ ___|" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "    " ANSI_WHITE "\\___ \\| |/ _` | '_ \\ / _ \\| __| | | \\___ \\" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "      " ANSI_WHITE "___) | | (_| | | | |  __/| |_| |_| |___) |" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "      " ANSI_WHITE "|____/|_|\\__, |_| |_|\\___| \\__|\\___/|____/" ANSI_RESET "\x1b[K\n"
     "                           " ANSI_WHITE "|___/" ANSI_RESET "   " ANSI_GRAY "v0.1  |  " ANSI_WHITE "▌" ANSI_RESET "\x1b[K\n",
     200},
    // Frame 19: Cursor blinks off
    {"     " ANSI_RED ".-----." ANSI_RESET "       " ANSI_WHITE "____  _                   _    ___  ____" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "/ .---. \\" ANSI_RESET "     " ANSI_WHITE "/ ___|(_) __ _ _ __   ___ | |_ / _ \\/ ___|" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "    " ANSI_WHITE "\\___ \\| |/ _` | '_ \\ / _ \\| __| | | \\___ \\" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "      " ANSI_WHITE "___) | | (_| | | | |  __/| |_| |_| |___) |" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "      " ANSI_WHITE "|____/|_|\\__, |_| |_|\\___| \\__|\\___/|____/" ANSI_RESET "\x1b[K\n"
     "                           " ANSI_WHITE "|___/" ANSI_RESET "   " ANSI_GRAY "v0.1  |  " ANSI_RESET "\x1b[K\n",
     180},
    // Frame 20: Typewriter starts: "(c) "
    {"     " ANSI_RED ".-----." ANSI_RESET "       " ANSI_WHITE "____  _                   _    ___  ____" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "/ .---. \\" ANSI_RESET "     " ANSI_WHITE "/ ___|(_) __ _ _ __   ___ | |_ / _ \\/ ___|" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "    " ANSI_WHITE "\\___ \\| |/ _` | '_ \\ / _ \\| __| | | \\___ \\" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "      " ANSI_WHITE "___) | | (_| | | | |  __/| |_| |_| |___) |" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "      " ANSI_WHITE "|____/|_|\\__, |_| |_|\\___| \\__|\\___/|____/" ANSI_RESET "\x1b[K\n"
     "                           " ANSI_WHITE "|___/" ANSI_RESET "   " ANSI_GRAY "v0.1  |  (c) " ANSI_WHITE "▌" ANSI_RESET "\x1b[K\n",
     70},
    // Frame 21: "(c) Goo"
    {"     " ANSI_RED ".-----." ANSI_RESET "       " ANSI_WHITE "____  _                   _    ___  ____" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "/ .---. \\" ANSI_RESET "     " ANSI_WHITE "/ ___|(_) __ _ _ __   ___ | |_ / _ \\/ ___|" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "    " ANSI_WHITE "\\___ \\| |/ _` | '_ \\ / _ \\| __| | | \\___ \\" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "      " ANSI_WHITE "___) | | (_| | | | |  __/| |_| |_| |___) |" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "      " ANSI_WHITE "|____/|_|\\__, |_| |_|\\___| \\__|\\___/|____/" ANSI_RESET "\x1b[K\n"
     "                           " ANSI_WHITE "|___/" ANSI_RESET "   " ANSI_GRAY "v0.1  |  (c) Goo" ANSI_WHITE "▌" ANSI_RESET "\x1b[K\n",
     65},
    // Frame 22: "(c) Google "
    {"     " ANSI_RED ".-----." ANSI_RESET "       " ANSI_WHITE "____  _                   _    ___  ____" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "/ .---. \\" ANSI_RESET "     " ANSI_WHITE "/ ___|(_) __ _ _ __   ___ | |_ / _ \\/ ___|" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "    " ANSI_WHITE "\\___ \\| |/ _` | '_ \\ / _ \\| __| | | \\___ \\" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "      " ANSI_WHITE "___) | | (_| | | | |  __/| |_| |_| |___) |" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "      " ANSI_WHITE "|____/|_|\\__, |_| |_|\\___| \\__|\\___/|____/" ANSI_RESET "\x1b[K\n"
     "                           " ANSI_WHITE "|___/" ANSI_RESET "   " ANSI_GRAY "v0.1  |  (c) Google " ANSI_WHITE "▌" ANSI_RESET "\x1b[K\n",
     70},
    // Frame 23: "(c) Google CH"
    {"     " ANSI_RED ".-----." ANSI_RESET "       " ANSI_WHITE "____  _                   _    ___  ____" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "/ .---. \\" ANSI_RESET "     " ANSI_WHITE "/ ___|(_) __ _ _ __   ___ | |_ / _ \\/ ___|" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "    " ANSI_WHITE "\\___ \\| |/ _` | '_ \\ / _ \\| __| | | \\___ \\" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "      " ANSI_WHITE "___) | | (_| | | | |  __/| |_| |_| |___) |" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "      " ANSI_WHITE "|____/|_|\\__, |_| |_|\\___| \\__|\\___/|____/" ANSI_RESET "\x1b[K\n"
     "                           " ANSI_WHITE "|___/" ANSI_RESET "   " ANSI_GRAY "v0.1  |  (c) Google CH" ANSI_WHITE "▌" ANSI_RESET "\x1b[K\n",
     65},
    // Frame 24: "(c) Google CHERI "
    {"     " ANSI_RED ".-----." ANSI_RESET "       " ANSI_WHITE "____  _                   _    ___  ____" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "/ .---. \\" ANSI_RESET "     " ANSI_WHITE "/ ___|(_) __ _ _ __   ___ | |_ / _ \\/ ___|" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "    " ANSI_WHITE "\\___ \\| |/ _` | '_ \\ / _ \\| __| | | \\___ \\" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "      " ANSI_WHITE "___) | | (_| | | | |  __/| |_| |_| |___) |" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "      " ANSI_WHITE "|____/|_|\\__, |_| |_|\\___| \\__|\\___/|____/" ANSI_RESET "\x1b[K\n"
     "                           " ANSI_WHITE "|___/" ANSI_RESET "   " ANSI_GRAY "v0.1  |  (c) Google CHERI " ANSI_WHITE "▌" ANSI_RESET "\x1b[K\n",
     70},
    // Frame 25: Full metadata typed + cursor
    {"     " ANSI_RED ".-----." ANSI_RESET "       " ANSI_WHITE "____  _                   _    ___  ____" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "/ .---. \\" ANSI_RESET "     " ANSI_WHITE "/ ___|(_) __ _ _ __   ___ | |_ / _ \\/ ___|" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "    " ANSI_WHITE "\\___ \\| |/ _` | '_ \\ / _ \\| __| | | \\___ \\" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "      " ANSI_WHITE "___) | | (_| | | | |  __/| |_| |_| |___) |" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "      " ANSI_WHITE "|____/|_|\\__, |_| |_|\\___| \\__|\\___/|____/" ANSI_RESET "\x1b[K\n"
     "                           " ANSI_WHITE "|___/" ANSI_RESET "   " ANSI_GRAY "v0.1  |  (c) Google CHERI Team " ANSI_WHITE "▌" ANSI_RESET "\x1b[K\n",
     150},
    // Frame 26: Cursor blinks off
    {"     " ANSI_RED ".-----." ANSI_RESET "       " ANSI_WHITE "____  _                   _    ___  ____" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "/ .---. \\" ANSI_RESET "     " ANSI_WHITE "/ ___|(_) __ _ _ __   ___ | |_ / _ \\/ ___|" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "    " ANSI_WHITE "\\___ \\| |/ _` | '_ \\ / _ \\| __| | | \\___ \\" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "      " ANSI_WHITE "___) | | (_| | | | |  __/| |_| |_| |___) |" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "      " ANSI_WHITE "|____/|_|\\__, |_| |_|\\___| \\__|\\___/|____/" ANSI_RESET "\x1b[K\n"
     "                           " ANSI_WHITE "|___/" ANSI_RESET "   " ANSI_GRAY "v0.1  |  (c) Google CHERI Team" ANSI_RESET "\x1b[K\n",
     150},
    // Frame 27: Cursor blinks on
    {"     " ANSI_RED ".-----." ANSI_RESET "       " ANSI_WHITE "____  _                   _    ___  ____" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "/ .---. \\" ANSI_RESET "     " ANSI_WHITE "/ ___|(_) __ _ _ __   ___ | |_ / _ \\/ ___|" ANSI_RESET "\x1b[K\n"
     "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "    " ANSI_WHITE "\\___ \\| |/ _` | '_ \\ / _ \\| __| | | \\___ \\" ANSI_RESET "\x1b[K\n"
     "    " ANSI_RED "\\ '---' /" ANSI_RESET "      " ANSI_WHITE "___) | | (_| | | | |  __/| |_| |_| |___) |" ANSI_RESET "\x1b[K\n"
     "     " ANSI_RED "'-----'" ANSI_RESET "      " ANSI_WHITE "|____/|_|\\__, |_| |_|\\___| \\__|\\___/|____/" ANSI_RESET "\x1b[K\n"
     "                           " ANSI_WHITE "|___/" ANSI_RESET "   " ANSI_GRAY "v0.1  |  (c) Google CHERI Team " ANSI_WHITE "▌" ANSI_RESET "\x1b[K\n",
     150},
};

inline constexpr const char* kFinalBody =
    "     " ANSI_RED ".-----." ANSI_RESET "       " ANSI_WHITE "____  _                   _    ___  ____" ANSI_RESET "\x1b[K\n"
    "    " ANSI_RED "/ .---. \\" ANSI_RESET "     " ANSI_WHITE "/ ___|(_) __ _ _ __   ___ | |_ / _ \\/ ___|" ANSI_RESET "\x1b[K\n"
    "   " ANSI_RED "| | " ANSI_GOLD "[S]" ANSI_RED " | |" ANSI_RESET "    " ANSI_WHITE "\\___ \\| |/ _` | '_ \\ / _ \\| __| | | \\___ \\" ANSI_RESET "\x1b[K\n"
    "    " ANSI_RED "\\ '---' /" ANSI_RESET "      " ANSI_WHITE "___) | | (_| | | | |  __/| |_| |_| |___) |" ANSI_RESET "\x1b[K\n"
    "     " ANSI_RED "'-----'" ANSI_RESET "      " ANSI_WHITE "|____/|_|\\__, |_| |_|\\___| \\__|\\___/|____/" ANSI_RESET "\x1b[K\n"
    "                           " ANSI_WHITE "|___/" ANSI_RESET "   " ANSI_GRAY "v0.1  |  (c) Google CHERI Team" ANSI_RESET "\x1b[K\n";

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
  out(ANSI_RESET);
  if (animate) {
    out("\x1b[?25h");
  }
}

#undef ANSI_RESET
#undef ANSI_RED
#undef ANSI_GOLD
#undef ANSI_WHITE
#undef ANSI_GRAY

}  // namespace signetos::logo
