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
 * heap_compat.hpp - what the vendored CHERIoT allocator needs from outside
 * itself (third_party/cheriot_allocator) and SignetOS does not have: a little
 * of the C++ standard library and of the CHERIoT SDK. Its files include this
 * where upstream includes those headers. Only what is used. In order:
 *
 *   the attribute macros     upstream: the CHERIoT SDK's <cdefs.h>
 *   the standard library     upstream: <cstddef>, <type_traits>, <concepts>,
 *                            <compare>, <new>
 *   utils::bytes_to_bits     upstream: the CHERIoT SDK's <utils.hh>
 *   EINVAL                   upstream: <errno.h>
 *   ConditionalDebug         upstream: the CHERIoT SDK's <debug.hh>
 */

#include <stddef.h>
#include <stdint.h>

// ============================================================================
// Attribute macros
// ============================================================================

// The BSD spellings the allocator and `ConditionalDebug` below use.

#define __noinline __attribute__((noinline))
#define __always_inline __attribute__((always_inline))
#define __packed __attribute__((packed))
#define __aligned(x) __attribute__((aligned(x)))
#define __cheri_no_subobject_bounds __attribute__((cheri_no_subobject_bounds))

#define __predict_false(exp) __builtin_expect((exp), 0)

// ============================================================================
// The C++ standard library
// ============================================================================

// SignetOS has no C++ standard library. The traits below are built on the
// compiler's builtins.

// --- <cstddef> ---------------------------------------------------------------

// The integer type of a capability's address, which a CHERI toolchain's own
// <stddef.h> defines but include/libc/stddef.h does not.
using ptraddr_t = __PTRADDR_TYPE__;

namespace std {

using ::size_t;
using nullptr_t = decltype(nullptr);

}  // namespace std

// --- <type_traits> -----------------------------------------------------------

namespace std {

template <typename T, typename U>
inline constexpr bool is_same_v = __is_same(T, U);

template <typename T>
inline constexpr bool is_standard_layout_v = __is_standard_layout(T);

template <typename T>
inline constexpr bool is_arithmetic_v = __is_arithmetic(T);

template <typename T>
inline constexpr bool is_integral_v = __is_integral(T);

template <typename T>
inline constexpr bool is_unsigned_v = __is_unsigned(T);

template <typename T>
using make_signed_t = __make_signed(T);

}  // namespace std

// --- <concepts> --------------------------------------------------------------

namespace std {

template <typename T, typename U>
concept same_as = is_same_v<T, U> && is_same_v<U, T>;

template <typename T>
concept integral = is_integral_v<T>;

}  // namespace std

// --- <compare> ---------------------------------------------------------------

// The type `<=>` gives for integers and pointers. The compiler looks it up by
// name, and the allocator's pointer proxies use `<=>` (ds/pointer.hpp). The
// compiler requires this shape: one integer member, the constants as static
// members.
namespace std {

class strong_ordering {
  signed char value_;

  constexpr explicit strong_ordering(signed char v) noexcept : value_(v) {}

 public:
  static const strong_ordering less;
  static const strong_ordering equal;
  static const strong_ordering equivalent;
  static const strong_ordering greater;

  friend constexpr bool operator==(strong_ordering,
                                   strong_ordering) noexcept = default;
};

inline constexpr strong_ordering strong_ordering::less{-1};
inline constexpr strong_ordering strong_ordering::equal{0};
inline constexpr strong_ordering strong_ordering::equivalent{0};
inline constexpr strong_ordering strong_ordering::greater{1};

}  // namespace std

// --- <new> -------------------------------------------------------------------

// Placement new, for the allocator's chunk headers and free-list nodes.
[[nodiscard]] inline void* operator new(std::size_t, void* p) noexcept {
  return p;
}

// ============================================================================
// utils
// ============================================================================

namespace utils {

constexpr size_t bytes_to_bits(size_t bytes) { return bytes * __CHAR_BIT__; }

}  // namespace utils

// ============================================================================
// errno
// ============================================================================

// The one error number the allocator returns, with its usual value.

#define EINVAL 22

// ============================================================================
// ConditionalDebug
// ============================================================================

// `ConditionalDebug`, as the allocator uses it:
//
//   Debug::log("text {} {}", a, b)                 a line, if enabled
//   Debug::Assert(condition, "text {}", a)         checked if enabled
//   Debug::Assert([&] { return ...; }, "text")     same; the lambda is not
//                                                  run when disabled
//   Debug::Invariant(condition, "text {}", a)      always checked
//   Debug::invariant(condition, "text {}", a)      the same, as a function
//
// A failed Assert or Invariant prints its message (if enabled) and traps; the
// compartment's fault handler reports and unwinds. Each `{}` is replaced by
// the next argument: integers in decimal, pointers (and what converts to one,
// such as a `CHERI::Capability`) as their address in hex.
//
// The text goes to `signetos_heap_debug_write`, defined by the image that
// embeds the allocator: the image knows where its console is. Only code built
// with debugging enabled calls it, so other images need not define it.

// Writes `line`, NUL-terminated and ending in a newline, to the console.
void signetos_heap_debug_write(const char* line);

namespace heap_debug {

// One `{}` argument.
struct Argument {
  enum Kind : uint8_t { Unsigned, Signed, Boolean, Address };
  Kind kind;
  uint64_t value;
};

template <std::integral T>
constexpr Argument argument(T v) {
  if constexpr (std::is_same_v<T, bool>) {
    return {Argument::Boolean, v};
  } else if constexpr (std::is_unsigned_v<T>) {
    return {Argument::Unsigned, v};
  } else {
    return {Argument::Signed, static_cast<uint64_t>(static_cast<int64_t>(v))};
  }
}

inline Argument argument(const volatile void* p) {
  return {Argument::Address, __builtin_cheri_address_get(p)};
}

// One line of text in a fixed buffer. What does not fit is dropped.
class Line {
  char buf_[224];
  size_t len_ = 0;

  void number(uint64_t v, uint64_t base) {
    char digits[20];  // UINT64_MAX has 20 decimal digits
    size_t n = 0;
    do {
      const uint64_t d = v % base;
      digits[n++] = static_cast<char>(d < 10 ? '0' + d : 'a' + (d - 10));
      v /= base;
    } while (v != 0);
    while (n > 0) {
      put(digits[--n]);
    }
  }

 public:
  void put(char c) {
    if (len_ + 2 < sizeof(buf_)) {  // room for the newline and the NUL
      buf_[len_++] = c;
    }
  }

  void text(const char* s) {
    for (; *s != '\0'; ++s) {
      put(*s);
    }
  }

  void decimal(uint64_t v) { number(v, 10); }

  void argument(const Argument& a) {
    switch (a.kind) {
      case Argument::Unsigned:
        number(a.value, 10);
        break;
      case Argument::Signed:
        if (static_cast<int64_t>(a.value) < 0) {
          put('-');
          number(0 - a.value, 10);
        } else {
          number(a.value, 10);
        }
        break;
      case Argument::Boolean:
        text(a.value != 0 ? "true" : "false");
        break;
      case Argument::Address:
        text("0x");
        number(a.value, 16);
        break;
    }
  }

  // `fmt`, with each `{}` replaced by the next of `args`.
  void format(const char* fmt, const Argument* args, size_t count) {
    size_t next = 0;
    for (const char* p = fmt; *p != '\0'; ++p) {
      if (p[0] == '{' && p[1] == '}' && next < count) {
        argument(args[next++]);
        ++p;
      } else {
        put(*p);
      }
    }
  }

  const char* finish() {
    buf_[len_++] = '\n';
    buf_[len_] = '\0';
    return buf_;
  }
};

// Prints "<context>: <fmt>", or for a failed check
// "<context>: <what> failed at <file>:<line>: <fmt>".
__noinline inline void write(const char* context, const char* what,
                             const char* file, int line, const char* fmt,
                             const Argument* args, size_t count) {
  Line out;
  out.text(context);
  out.text(": ");
  if (what != nullptr) {
    out.text(what);
    out.text(" failed");
    if (file != nullptr) {
      out.text(" at ");
      out.text(file);
      out.put(':');
      out.decimal(static_cast<uint64_t>(line));
    }
    out.text(": ");
  }
  out.format(fmt, args, count);
  signetos_heap_debug_write(out.finish());
}

template <typename T>
concept LazyCondition = requires(T f) {
  { f() } -> std::same_as<bool>;
};

}  // namespace heap_debug

// A string literal as a template argument: the name a `ConditionalDebug`
// prints in front of its lines.
template <size_t N>
struct DebugContext {
  char text[N];
  constexpr DebugContext(const char (&s)[N]) {
    for (size_t i = 0; i < N; ++i) {
      text[i] = s[i];
    }
  }
};

template <bool Enabled, DebugContext Context, bool EnableAssertions = Enabled,
          bool VerboseInvariants = Enabled>
class ConditionalDebug {
  static void report(const char* what, const char* file, int line,
                     const char* fmt, auto... args) {
    // One spare element: an array of none is not allowed.
    const heap_debug::Argument list[sizeof...(args) + 1] = {
        heap_debug::argument(args)...};
    heap_debug::write(Context.text, what, file, line, fmt, list,
                      sizeof...(args));
  }

 public:
  static void log(const char* fmt, auto... args) {
    if constexpr (Enabled) {
      report(nullptr, nullptr, 0, fmt, args...);
    }
  }

  template <typename... Args>
  struct Invariant {
    __always_inline Invariant(bool condition, const char* fmt, Args... args,
                              const char* file = __builtin_FILE(),
                              int line = __builtin_LINE()) {
      if (__predict_false(!condition)) {
        if constexpr (VerboseInvariants) {
          report("Invariant", file, line, fmt, args...);
        }
        __builtin_trap();
      }
    }
  };

  template <typename... Args>
  struct Assert {
    template <std::same_as<bool> T>
    __always_inline Assert(T condition, const char* fmt, Args... args,
                           const char* file = __builtin_FILE(),
                           int line = __builtin_LINE()) {
      if constexpr (EnableAssertions) {
        if (__predict_false(!condition)) {
          report("Assertion", file, line, fmt, args...);
          __builtin_trap();
        }
      }
    }

    template <heap_debug::LazyCondition T>
    __always_inline Assert(T&& condition, const char* fmt, Args... args,
                           const char* file = __builtin_FILE(),
                           int line = __builtin_LINE()) {
      if constexpr (EnableAssertions) {
        if (__predict_false(!condition())) {
          report("Assertion", file, line, fmt, args...);
          __builtin_trap();
        }
      }
    }
  };

  // So that `Invariant(...)` and `Assert(...)` can be written like calls.
  template <typename T, typename... Ts>
  Invariant(T, const char*, Ts...) -> Invariant<Ts...>;
  template <typename... Ts>
  Assert(bool, const char*, Ts...) -> Assert<Ts...>;
  template <typename... Ts>
  Assert(auto, const char*, Ts...) -> Assert<Ts...>;

  // `Invariant` as a function, for where the class cannot be named like a
  // call (through a type that depends on a template parameter).
  __always_inline static void invariant(bool condition, const char* fmt,
                                        auto... args) {
    if (__predict_false(!condition)) {
      if constexpr (VerboseInvariants) {
        report("Invariant", nullptr, 0, fmt, args...);
      }
      __builtin_trap();
    }
  }
};
