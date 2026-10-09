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

#ifndef SIGNETOS_LIBC_STDDEF_H
#define SIGNETOS_LIBC_STDDEF_H

#define NULL ((void*)0)
typedef unsigned long size_t;
typedef long ptrdiff_t;
/* The compiler builtin: a constant expression, so it can be static_asserted
 * (the classic null-pointer cast is not one in C++). */
#define offsetof(type, member) __builtin_offsetof(type, member)

#endif
