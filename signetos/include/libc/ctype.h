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

#ifndef SIGNETOS_LIBC_CTYPE_H
#define SIGNETOS_LIBC_CTYPE_H

static inline int isdigit(int c) { return (c >= '0' && c <= '9'); }
static inline int isalpha(int c) { return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')); }
static inline int isalnum(int c) { return isdigit(c) || isalpha(c); }
static inline int isspace(int c) { return (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'); }
static inline int islower(int c) { return (c >= 'a' && c <= 'z'); }
static inline int isupper(int c) { return (c >= 'A' && c <= 'Z'); }
static inline int tolower(int c) { return isupper(c) ? (c - 'A' + 'a') : c; }
static inline int toupper(int c) { return islower(c) ? (c - 'a' + 'A') : c; }
static inline int isprint(int c) { return (c >= 32 && c < 127); }

#endif
