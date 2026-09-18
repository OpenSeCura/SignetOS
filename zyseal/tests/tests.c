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


/*
 * tests.c - Zyseal tests, written as flat inline assembly so the source
 * maps one-to-one onto the disassembly. `make show` to check that.
 *
 *   yseal   rd, rs1, rs2    rd = rs2 with CT set to rs1's address
 *   yunseal rd, rs1, rs2    rd = rs2 with CT set to 0
 *
 * rs1 is the authority: its address is the type, its bounds are the types it
 * may name, SE (perm bit 24) lets it seal and US (bit 25) lets it unseal.
 * CT is 4 bits: 0 = unsealed, 1 = sentry, 2..15 = objects. Neither instruction
 * traps; on refusal they write rs2 to rd with the tag cleared.
 *
 * THE TESTS
 *   T1, T2    yseal sets CT and changes nothing else; yunseal puts it back
 *   T3, T4    SE and US are enforced
 *   T5 - T7   the authority must be entitled to the type it names
 *   T8        reserved and out-of-range type numbers are refused
 *   T30       ...and so are all 32 values of CT, exhaustively
 *   T9 - T12  a sealed capability cannot be loaded from or stored through
 *   T13 - T15 nor jumped to -- unlike a sentry, which still works
 *   T16       CT lives in the 128-bit encoding, not in emulator state
 *   T17, T18  cbld cannot forge a sealed capability
 *   T28       SE and US sit at permission bits 24 and 25
 *   T29       yunseal clears GL for a local authority (Zylevels1 only)
 */

typedef void *__capability cap_t;
typedef unsigned long long u64;
typedef unsigned int u32;
typedef volatile unsigned char *__capability uart_t;

#define UART_BASE 0x10000000ULL
#define TEST_BASE 0x00100000ULL

/*
 * Seal / unseal permission masks.  Spec Figure 16 puts US at permission bit
 * 25 and SE at bit 24 (bits 10/11 are Reserved-ONE and would read as set on
 * every capability).  Take these from the compiler rather than hardcoding, so
 * the test cannot drift from the toolchain.
 */
#define SE ((u64)__CHERI_CAP_PERMISSION_SEAL__)     /* 1 << 24 */
#define US ((u64)__CHERI_CAP_PERMISSION_UNSEAL__)   /* 1 << 25 */

/*
 * GL, the global flag, is permission bit 4.  It only means anything with
 * Zylevels1; otherwise it reads as permanently set and acperm cannot clear it.
 * clang only defines the macro when zcherilevels is in -march.
 */
#if defined(__CHERI_CAP_PERMISSION_CAPABILITY_LEVEL__)
#define GL ((u64)__CHERI_CAP_PERMISSION_CAPABILITY_LEVEL__)
#else
#define GL (1ULL << 4)
#endif

/* Written by trap.S through the reserved register cs9. [0]=trapped, [1]=scause */
volatile u64 g_trap_state[2] __attribute__((aligned(16)));

static u64 g_buf[8] __attribute__((aligned(16)));   /* the object we seal */
static cap_t g_slot __attribute__((aligned(16)));   /* scratch for csc/clc */

static int g_pass, g_fail;

/* ---- printing scaffolding; nothing capability-related happens here ------ */

static void put_ch(uart_t u, char c)
{
    if (c == '\n') {
        while ((u[5] & 0x20) == 0) {
        }
        u[0] = '\r';
    }
    while ((u[5] & 0x20) == 0) {
    }
    u[0] = (unsigned char)c;
}

static void put_str(uart_t u, const char *s)
{
    while (*s) {
        put_ch(u, *s++);
    }
}

static void put_hex(uart_t u, u64 v)
{
    put_str(u, "0x");
    for (int i = 15; i >= 0; --i) {
        unsigned d = (unsigned)((v >> (i * 4)) & 0xf);
        put_ch(u, d < 10 ? (char)('0' + d) : (char)('a' + d - 10));
    }
}

static void put_dec(uart_t u, u64 v)
{
    char buf[21];
    int n = 0;
    if (v == 0) {
        put_ch(u, '0');
        return;
    }
    while (v) {
        buf[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (n) {
        put_ch(u, buf[--n]);
    }
}

/* Always prints both values, so you can see the numbers rather than trust me. */
static void report(uart_t u, const char *name, u64 got, u64 want)
{
    if (got == want) {
        ++g_pass;
        put_str(u, "[PASS] ");
    } else {
        ++g_fail;
        put_str(u, "[FAIL] ");
    }
    put_str(u, name);
    put_str(u, "   got=");
    put_hex(u, got);
    put_str(u, " want=");
    put_hex(u, want);
    put_ch(u, '\n');
}

/* The jump target for the cjalr tests. Compiles to a single `ret`. */
__attribute__((noinline, used)) static void probe_ret(void)
{
    __asm__ volatile("" ::: "memory");
}

/* ========================================================================
 * T1, T2 - the instruction does what it says.
 *
 * yseal stamps the authority's address into CT and changes NOTHING else;
 * yunseal with the matching authority puts CT back to 0.
 * ======================================================================== */
static void test_seal_sets_type_and_nothing_else(uart_t u, cap_t obj,
                                                 cap_t auth, cap_t auth_gl)
{
    u64 tag, type, base, len, perm;

    put_str(u, "-- the instruction does what it says --\n");

    __asm__ volatile(
        "yseal    ca2, %[auth], %[obj]   \n\t"  /* ==== THE INSTRUCTION ==== */
        "gctag    %[tag],  ca2           \n\t"
        "gctype   %[type], ca2           \n\t"
        "gcbase   %[base], ca2           \n\t"
        "gclen    %[len],  ca2           \n\t"
        "gcperm   %[perm], ca2           \n\t"
        : [tag]"=&r"(tag), [type]"=&r"(type), [base]"=&r"(base),
          [len]"=&r"(len), [perm]"=&r"(perm)
        : [auth]"C"(auth), [obj]"C"(obj)
        : "ca2");
    report(u, "T1a yseal keeps the tag         ", tag, 1);
    report(u, "T1b yseal sets CT to 2          ", type, 2);
    report(u, "T1c yseal leaves base alone     ", base,
           (u64)__builtin_cheri_base_get(obj));
    report(u, "T1d yseal leaves length alone   ", len,
           (u64)__builtin_cheri_length_get(obj));
    report(u, "T1e yseal leaves perms alone    ", perm,
           (u64)__builtin_cheri_perms_get(obj));

    /* auth_gl, not auth: a local authority would make yunseal strip GL under
     * Zylevels1, which is T29's subject rather than T2's. */
    __asm__ volatile(
        "yseal    ca2, %[auth], %[obj]   \n\t"  /* seal it   */
        "yunseal  ca3, %[auth], ca2      \n\t"  /* unseal it */
        "gctag    %[tag],  ca3           \n\t"
        "gctype   %[type], ca3           \n\t"
        "gcbase   %[base], ca3           \n\t"
        "gclen    %[len],  ca3           \n\t"
        "gcperm   %[perm], ca3           \n\t"
        : [tag]"=&r"(tag), [type]"=&r"(type), [base]"=&r"(base),
          [len]"=&r"(len), [perm]"=&r"(perm)
        : [auth]"C"(auth_gl), [obj]"C"(obj)
        : "ca2", "ca3");
    report(u, "T2a yunseal keeps the tag       ", tag, 1);
    report(u, "T2b yunseal sets CT back to 0   ", type, 0);
    /*
     * T2c-e: what comes back must be the ORIGINAL object. A yunseal that
     * returned something derived from the authority would still be tagged
     * and unsealed, so T2a/T2b alone would not notice.
     */
    report(u, "T2c yunseal restores base       ", base,
           (u64)__builtin_cheri_base_get(obj));
    report(u, "T2d yunseal restores length     ", len,
           (u64)__builtin_cheri_length_get(obj));
    report(u, "T2e yunseal restores perms      ", perm,
           (u64)__builtin_cheri_perms_get(obj));
}

/* ========================================================================
 * T3, T4 - the SE and US permissions are actually enforced.
 *
 * Each pair first proves the permission really is absent, then that the
 * operation refuses. Otherwise "it failed" could just mean the setup broke.
 * ======================================================================== */
static void test_permissions_are_checked(uart_t u, cap_t obj, cap_t auth)
{
    u64 tag, perm, atag;

    put_str(u, "-- permissions are checked --\n");

    /* T3: the shared authority with SE masked out. One bit different. */
    __asm__ volatile(
        "acperm   ca1, %[auth], %[us_only] \n\t"  /* US but NOT SE            */
        "gctag    %[atag], ca1             \n\t"  /* acperm did not invalidate */
        "gcperm   %[perm], ca1             \n\t"  /* prove SE really is gone  */
        "yseal    ca2, ca1, %[obj]         \n\t"
        "gctag    %[tag], ca2              \n\t"
        : [tag]"=&r"(tag), [perm]"=&r"(perm), [atag]"=&r"(atag)
        : [auth]"C"(auth), [obj]"C"(obj), [us_only]"r"(US)
        : "ca1", "ca2");
    report(u, "T3a authority is still tagged   ", atag, 1);
    report(u, "T3b authority really lacks SE   ", perm & SE, 0);
    report(u, "T3c yseal without SE -> tag 0   ", tag, 0);

    /*
     * T4: seal with the shared authority, then try to unseal with the same
     * capability with US masked off.
     */
    __asm__ volatile(
        "yseal    ca2, %[auth], %[obj]     \n\t"  /* seal with it             */
        "acperm   ca3, %[auth], %[se_only] \n\t"  /* same but SE only         */
        "gctag    %[atag], ca3             \n\t"
        "gcperm   %[perm], ca3             \n\t"
        "yunseal  ca4, ca3, ca2            \n\t"
        "gctag    %[tag], ca4              \n\t"
        : [tag]"=&r"(tag), [perm]"=&r"(perm), [atag]"=&r"(atag)
        : [auth]"C"(auth), [obj]"C"(obj), [se_only]"r"(SE)
        : "ca2", "ca3", "ca4");
    report(u, "T4a authority is still tagged   ", atag, 1);
    report(u, "T4b authority really lacks US   ", perm & US, 0);
    report(u, "T4c yunseal without US -> tag 0 ", tag, 0);
}

/* ========================================================================
 * T5, T6, T7 - the authority must be ENTITLED to the type it names.
 *
 * Three distinct ways to be unentitled:
 *   T5  address outside the authority's own bounds
 *   T6  right type, but bounds that never covered it   <- unforgeability
 *   T7  wrong type entirely
 *
 * Each case first reads back the authority's own tag, so a refusal can never
 * be credited to the authority having been invalidated while it was built.
 * ======================================================================== */
static void test_authority_must_be_entitled(uart_t u, cap_t root, cap_t obj,
                                            cap_t auth)
{
    u64 tag, perm;

    put_str(u, "-- the authority must be entitled to the type --\n");

    /*
     * T5: the shared authority, entitled to [2,18), with its address moved to
     * 900. Still tagged, unsealed and holding SE. Only the address is wrong.
     */
    __asm__ volatile(
        "scaddr   ca1, %[auth], %[nine00] \n\t"  /* address 900, out of bounds */
        "gctag    %[perm], ca1            \n\t"  /* authority itself still ok  */
        "yseal    ca2, ca1, %[obj]        \n\t"
        "gctag    %[tag], ca2             \n\t"
        : [tag]"=&r"(tag), [perm]"=&r"(perm)
        : [auth]"C"(auth), [obj]"C"(obj), [nine00]"r"(900ULL)
        : "ca1", "ca2");
    report(u, "T5a authority is still tagged   ", perm, 1);
    report(u, "T5b address out of bounds -> 0  ", tag, 0);

    /*
     * T6: an authority with US, tagged, unsealed, address EXACTLY 2 - the
     * right type - but whose bounds are [20,36) so it was never entitled to 2.
     * Built from root rather than the shared authority, because the wrong
     * bounds are the point.
     *
     * T6a is the control. Moving the address to 2 puts it outside the bounds,
     * and an out-of-bounds address must NOT by itself clear the tag - only an
     * unrepresentable one does. Without T6a, T6b would also pass if the
     * authority were simply untagged, which proves nothing about bounds.
     */
    __asm__ volatile(
        "yseal    ca2, %[auth], %[obj]   \n\t"  /* legitimate type-2 object */

        "scaddr   ca3, %[root], %[twenty]\n\t"  /* now the bogus authority: */
        "scbndsr  ca3, ca3, %[sixteen]   \n\t"  /*   bounds [20,36)         */
        "acperm   ca3, ca3, %[seus]      \n\t"  /*   has US                 */
        "scaddr   ca3, ca3, %[two]       \n\t"  /*   address 2 - right type */
        "gctag    %[perm], ca3           \n\t"  /*   ...and still tagged    */
        "yunseal  ca4, ca3, ca2          \n\t"
        "gctag    %[tag], ca4            \n\t"
        : [tag]"=&r"(tag), [perm]"=&r"(perm)
        : [root]"C"(root), [auth]"C"(auth), [obj]"C"(obj),
          [two]"r"(2ULL), [twenty]"r"(20ULL), [sixteen]"r"(16ULL),
          [seus]"r"(SE | US)
        : "ca2", "ca3", "ca4");
    report(u, "T6a bogus authority is tagged   ", perm, 1);
    report(u, "T6b right type, bad bounds -> 0 ", tag, 0);

    /* T7: authority names 3, object is type 2. Address 3 is inside [2,18),
     * so T7a should be uncontroversial - it is here to rule out the same
     * "failed because untagged" reading as T6a. */
    __asm__ volatile(
        "yseal    ca2, %[auth], %[obj]   \n\t"  /* object is type 2         */
        "scaddr   ca3, %[auth], %[three] \n\t"  /* same authority, type 3   */
        "gctag    %[perm], ca3           \n\t"
        "yunseal  ca4, ca3, ca2          \n\t"
        "gctag    %[tag], ca4            \n\t"
        : [tag]"=&r"(tag), [perm]"=&r"(perm)
        : [auth]"C"(auth), [obj]"C"(obj), [three]"r"(3ULL)
        : "ca2", "ca3", "ca4");
    report(u, "T7a type-3 authority is tagged  ", perm, 1);
    report(u, "T7b wrong type (3 vs 2) -> 0    ", tag, 0);
}

/* ========================================================================
 * T8 - spot checks on reserved and out-of-range type numbers.
 *
 *   type 1  = the sentry type; yseal must not mint it
 *   type 16 = one past the 4-bit maximum
 *   type 18 = would alias type 2 if the field were truncated: 18 & 15 == 2
 *   type 15 = the 4-bit maximum, which must work
 *
 * The `wide` authority is entitled to [0,64) so all four addresses are IN
 * BOUNDS. Any refusal therefore comes from the type-range check, not bounds.
 *
 * T30 below does this exhaustively; T8 is kept because these four are the
 * cases worth being able to see individually when something breaks.
 * ======================================================================== */
static void test_reserved_and_out_of_range_types(uart_t u, cap_t obj, cap_t wide)
{
    u64 t1, t16, t18, t15;

    put_str(u, "-- reserved and out-of-range types --\n");
    __asm__ volatile(
        "scaddr   ca2, %[wide], %[one]   \n\t"
        "yseal    ca3, ca2, %[obj]       \n\t"
        "gctag    %[r1], ca3             \n\t"

        "scaddr   ca2, %[wide], %[m16]   \n\t"
        "yseal    ca3, ca2, %[obj]       \n\t"
        "gctag    %[r16], ca3            \n\t"

        "scaddr   ca2, %[wide], %[m18]   \n\t"
        "yseal    ca3, ca2, %[obj]       \n\t"
        "gctag    %[r18], ca3            \n\t"

        "scaddr   ca2, %[wide], %[m15]   \n\t"
        "yseal    ca3, ca2, %[obj]       \n\t"
        "gctype   %[r15], ca3            \n\t"
        : [r1]"=&r"(t1), [r16]"=&r"(t16),
          [r18]"=&r"(t18), [r15]"=&r"(t15)
        : [wide]"C"(wide), [obj]"C"(obj),
          [one]"r"(1ULL), [m16]"r"(16ULL), [m18]"r"(18ULL), [m15]"r"(15ULL)
        : "ca2", "ca3");
    report(u, "T8a type 1 (sentry) refused     ", t1, 0);
    report(u, "T8b type 16 refused (past max)  ", t16, 0);
    report(u, "T8c type 18 refused (no alias)  ", t18, 0);
    report(u, "T8d type 15 (4-bit max) accepted", t15, 15);
}

/* ========================================================================
 * T30 - EVERY CT value, exhaustively. No spot checks.
 *
 * CT is 4 bits, so there are exactly 16 encodable values:
 *
 *     0        unsealed      yseal must refuse (0 means "not sealed")
 *     1        sentry        reserved by the base architecture; must refuse
 *     2..15    object types  must be accepted, with CT set to exactly t
 *
 * and every value from 16 up must be REFUSED rather than truncated into that
 * range. Truncation is the dangerous failure: 16->0, 17->1, 18->2, ... 31->15.
 * If type 18 quietly became type 2, one compartment could open another's
 * objects. So the sweep runs 0..31 and checks all 32.
 *
 * The authority has bounds [0,64), so every value tested is IN BOUNDS and the
 * only thing that can reject it is the type-range check itself.
 *
 * Then, for the 14 usable types:
 *   - each must round-trip back to CT 0 through yunseal
 *   - no type may unseal an object sealed with a DIFFERENT type. That is all
 *     14*13 = 182 ordered pairs, not a sample.
 * ======================================================================== */
static void test_every_ct_value(uart_t u, cap_t obj, cap_t wide)
{
    u64 low_accepted = 0;    /* types 0,1   wrongly sealed                 */
    u64 mid_sealed = 0;      /* types 2..15 sealed with the exact CT       */
    u64 high_accepted = 0;   /* types 16..31 wrongly sealed                */
    u64 round_tripped = 0;   /* types 2..15 that yunseal restored          */
    u64 cross_unsealed = 0;  /* pairs where the WRONG type unsealed        */
    u64 pairs_tried = 0;

    put_str(u, "-- every CT value (exhaustive sweep, 0..31) --\n");

    for (u64 t = 0; t < 32; ++t) {
        u64 tag, ct;
        __asm__ volatile(
            "scaddr   ca1, %[wide], %[t]   \n\t"  /* name type t            */
            "yseal    ca2, ca1, %[obj]     \n\t"
            "gctag    %[tag], ca2          \n\t"
            "gctype   %[ct],  ca2          \n\t"
            : [tag]"=&r"(tag), [ct]"=&r"(ct)
            : [wide]"C"(wide), [obj]"C"(obj), [t]"r"(t)
            : "ca1", "ca2");

        if (t < 2) {
            low_accepted += (tag != 0);
        } else if (t <= 15) {
            /* Both conditions matter: tagged AND the exact type, not an alias. */
            mid_sealed += (tag == 1 && ct == t);
        } else {
            high_accepted += (tag != 0);
        }
    }

    report(u, "T30a types 0 and 1 are refused          ", low_accepted, 0);
    report(u, "T30b all of 2..15 seal with exact CT    ", mid_sealed, 14);
    report(u, "T30c types 16..31 refused, not truncated", high_accepted, 0);

    for (u64 t = 2; t <= 15; ++t) {
        cap_t sealed_t;
        u64 tag, ct;

        __asm__ volatile(
            "scaddr   ca1, %[wide], %[t]   \n\t"
            "yseal    %[out], ca1, %[obj]  \n\t"  /* seal with type t    */
            "yunseal  ca2, ca1, %[out]     \n\t"  /* and open it again   */
            "gctag    %[tag], ca2          \n\t"
            "gctype   %[ct],  ca2          \n\t"
            : [out]"=&C"(sealed_t), [tag]"=&r"(tag), [ct]"=&r"(ct)
            : [wide]"C"(wide), [obj]"C"(obj), [t]"r"(t)
            : "ca1", "ca2");
        round_tripped += (tag == 1 && ct == 0);

        /* Now every OTHER type must fail to open it. */
        for (u64 other = 2; other <= 15; ++other) {
            u64 otag;
            if (other == t) {
                continue;
            }
            __asm__ volatile(
                "scaddr   ca1, %[wide], %[o]   \n\t"
                "yunseal  ca2, ca1, %[sc]      \n\t"
                "gctag    %[tag], ca2          \n\t"
                : [tag]"=&r"(otag)
                : [wide]"C"(wide), [sc]"C"(sealed_t), [o]"r"(other)
                : "ca1", "ca2");
            cross_unsealed += (otag != 0);
            ++pairs_tried;
        }
    }

    report(u, "T30d all of 2..15 round-trip to CT 0    ", round_tripped, 14);
    put_str(u, "       cross-type attempts made = ");
    put_dec(u, pairs_tried);
    put_ch(u, '\n');
    report(u, "T30e no type ever unsealed another      ", cross_unsealed, 0);
}

/* ========================================================================
 * T9 - T12 - A SEALED CAPABILITY CANNOT BE DEREFERENCED.
 *
 * This is the property that matters. Everything above only reads fields back;
 * this actually tries to USE the thing.
 *
 * The trap handler (trap.S) sets g_trap_state[0] and skips the faulting
 * instruction, so control returns here either way.
 *
 * ".option norvc" forces the 4-byte form of each memory instruction, because
 * trap.S resumes at sepcc+4.
 * ======================================================================== */
static void test_sealed_capability_is_unusable(uart_t u, cap_t obj, cap_t auth)
{
    u64 trapped, scause, dummy;
    cap_t sealed, opened;

    put_str(u, "-- a sealed capability cannot be used --\n");

    /* T9a control: the UNSEALED object must load fine. */
    g_trap_state[0] = 0;
    __asm__ volatile(
        ".option push          \n\t"
        ".option norvc         \n\t"
        "ld  %[dst], 0(%[c])   \n\t"
        ".option pop           \n\t"
        : [dst]"=r"(dummy)
        : [c]"C"(obj)
        : "memory");
    trapped = g_trap_state[0];
    report(u, "T9a control: unsealed ld works  ", trapped, 0);

    /* Build the sealed capability once, into a C variable, for T9b..T12. */
    __asm__ volatile(
        "yseal    %[out], %[auth], %[obj] \n\t"
        : [out]"=C"(sealed)
        : [auth]"C"(auth), [obj]"C"(obj));

    /* T9b: load through it must fault. */
    g_trap_state[0] = 0;
    __asm__ volatile(
        ".option push          \n\t"
        ".option norvc         \n\t"
        "ld  %[dst], 0(%[c])   \n\t"
        ".option pop           \n\t"
        : [dst]"=r"(dummy)
        : [c]"C"(sealed)
        : "memory");
    trapped = g_trap_state[0];
    scause = g_trap_state[1];
    report(u, "T9b ld through sealed FAULTS    ", trapped, 1);
    report(u, "T9c ...with a CHERI fault cause ", scause, 0x1c);

    /* T10: store through it must fault. */
    g_trap_state[0] = 0;
    __asm__ volatile(
        ".option push          \n\t"
        ".option norvc         \n\t"
        "sd  zero, 0(%[c])     \n\t"
        ".option pop           \n\t"
        :
        : [c]"C"(sealed)
        : "memory");
    trapped = g_trap_state[0];
    report(u, "T10 sd through sealed FAULTS    ", trapped, 1);

    /* T11: capability load through it must fault (separate instruction). */
    g_trap_state[0] = 0;
    __asm__ volatile(
        ".option push          \n\t"
        ".option norvc         \n\t"
        "clc ca1, 0(%[c])      \n\t"
        ".option pop           \n\t"
        :
        : [c]"C"(sealed)
        : "ca1", "memory");
    trapped = g_trap_state[0];
    report(u, "T11 clc through sealed FAULTS   ", trapped, 1);

    /* T12: after yunseal it works again - so sealing locks, not destroys. */
    __asm__ volatile(
        "yunseal  %[out], %[auth], %[sc] \n\t"
        : [out]"=C"(opened)
        : [auth]"C"(auth), [sc]"C"(sealed));
    g_trap_state[0] = 0;
    __asm__ volatile(
        ".option push          \n\t"
        ".option norvc         \n\t"
        "ld  %[dst], 0(%[c])   \n\t"
        ".option pop           \n\t"
        : [dst]"=r"(dummy)
        : [c]"C"(opened)
        : "memory");
    trapped = g_trap_state[0];
    report(u, "T12 ld after yunseal works      ", trapped, 0);
}

/* ========================================================================
 * T13 - T15 - a sealed capability is NOT a sentry.
 *
 * Our design: sentries are CT=1; Zyseal objects are CT>=2. If QEMU treated any
 * non-zero type as a sentry, a cjalr to a sealed object would succeed AND
 * unseal it on arrival.
 *
 * cjalr writes the return address to cra, hence the "ra" clobber.
 * probe_ret is a single `ret`, so if the jump is allowed we come back.
 * ======================================================================== */
static void test_sealed_is_not_a_sentry(uart_t u, cap_t code_root, cap_t auth)
{
    u64 trapped, type;
    cap_t exec, sealed_exec, sentry;

    put_str(u, "-- a sealed capability is not a sentry --\n");

    /* An unsealed, executable capability aimed at probe_ret. */
    void (*fp)(void) = probe_ret;
    u64 code_addr = __builtin_cheri_address_get((cap_t)fp);
    __asm__ volatile("scaddr %[out], %[cr], %[a]"
                     : [out]"=C"(exec)
                     : [cr]"C"(code_root), [a]"r"(code_addr));

    /* T13 control: jumping to it works. */
    g_trap_state[0] = 0;
    __asm__ volatile(
        ".option push          \n\t"
        ".option norvc         \n\t"
        "cjalr cra, %[c]       \n\t"
        ".option pop           \n\t"
        :
        : [c]"C"(exec)
        : "ra", "memory");
    trapped = g_trap_state[0];
    report(u, "T13 control: cjalr to code works", trapped, 0);

    /* T14: seal that same executable capability, then jump -> must fault. */
    __asm__ volatile(
        "yseal    %[out], %[auth], %[e]  \n\t"
        : [out]"=C"(sealed_exec)
        : [auth]"C"(auth), [e]"C"(exec));
    g_trap_state[0] = 0;
    __asm__ volatile(
        ".option push          \n\t"
        ".option norvc         \n\t"
        "cjalr cra, %[c]       \n\t"
        ".option pop           \n\t"
        :
        : [c]"C"(sealed_exec)
        : "ra", "memory");
    trapped = g_trap_state[0];
    report(u, "T14 cjalr to SEALED cap FAULTS  ", trapped, 1);

    /* T15 control: a real sentry (CT=1) must STILL be callable. */
    __asm__ volatile("sentry %[out], %[e]"
                     : [out]"=C"(sentry)
                     : [e]"C"(exec));
    __asm__ volatile("gctype %[t], %[c]" : [t]"=r"(type) : [c]"C"(sentry));
    g_trap_state[0] = 0;
    __asm__ volatile(
        ".option push          \n\t"
        ".option norvc         \n\t"
        "cjalr cra, %[c]       \n\t"
        ".option pop           \n\t"
        :
        : [c]"C"(sentry)
        : "ra", "memory");
    trapped = g_trap_state[0];
    report(u, "T15a a sentry has CT 1          ", type, 1);
    report(u, "T15b control: cjalr to sentry ok", trapped, 0);
}

/* ========================================================================
 * T16 - CT really lives in the 128-bit architectural encoding.
 *
 * This is not a test that memory works. A QEMU cap_register_t carries both a
 * decoded struct AND the packed cr_pesbt word. Had CT been stored only in the
 * decoded half, every in-register check above would still pass, because they
 * all read it back through gctype without the value ever being re-encoded.
 *
 * csc writes the architectural 128 bits out and clc decodes them back, so it
 * is the cheapest way to force a full encode/decode cycle and prove CT is in
 * the real format rather than in emulator-side state.
 * ======================================================================== */
static void test_type_survives_memory(uart_t u, cap_t obj, cap_t slot, cap_t auth)
{
    u64 tag, type;
    cap_t sealed;

    put_str(u, "-- CT is in the architectural encoding, not emulator state --\n");

    __asm__ volatile(
        "yseal    %[out], %[auth], %[obj] \n\t"
        : [out]"=C"(sealed)
        : [auth]"C"(auth), [obj]"C"(obj));

    __asm__ volatile(
        "csc      %[sc], 0(%[slot])      \n\t"  /* store the sealed cap    */
        "clc      ca2, 0(%[slot])        \n\t"  /* load it back            */
        "gctag    %[tag],  ca2           \n\t"
        "gctype   %[type], ca2           \n\t"
        : [tag]"=&r"(tag), [type]"=&r"(type)
        : [sc]"C"(sealed), [slot]"C"(slot)
        : "ca2", "memory");
    report(u, "T16a tag survives csc/clc       ", tag, 1);
    report(u, "T16b CT survives csc/clc        ", type, 2);
}

/* ========================================================================
 * T17, T18 - cbld must not forge a sealed capability.
 *
 * cbld rd, rs1, rs2 rebuilds a tagged capability from an UNTAGGED template
 * rs2, if the authority rs1 could have derived it. CT occupies bits that are
 * outside the reserved field, so cbld's reserved-bit check does not cover it.
 * Check it still refuses.
 * ======================================================================== */
static void test_cbld_cannot_forge(uart_t u, cap_t root, cap_t obj, cap_t auth)
{
    u64 tag, type;
    cap_t sealed;

    put_str(u, "-- cbld cannot forge a sealed capability --\n");

    __asm__ volatile(
        "yseal    %[out], %[auth], %[obj] \n\t"
        : [out]"=C"(sealed)
        : [auth]"C"(auth), [obj]"C"(obj));

    /*
     * The template: a sealed capability with its tag cleared. Tag-clearing is
     * unprivileged, so this is exactly what an attacker could hold. It still
     * carries CT=2 in its bits, which is the pattern cbld must refuse.
     */
    cap_t templ = __builtin_cheri_tag_clear(sealed);
    __asm__ volatile("gctype %[t], %[c]" : [t]"=r"(type) : [c]"C"(templ));
    __asm__ volatile("gctag  %[t], %[c]" : [t]"=r"(tag)  : [c]"C"(templ));
    report(u, "T17a template: untagged         ", tag, 0);
    report(u, "T17b template: still carries CT2", type, 2);

    __asm__ volatile(
        "cbld   ca2, %[root], %[t]       \n\t"
        "gctag  %[tag], ca2              \n\t"
        : [tag]"=&r"(tag)
        : [root]"C"(root), [t]"C"(templ)
        : "ca2");
    report(u, "T17c cbld REFUSES to forge it   ", tag, 0);

    /* T18 control: cbld must still work for an ordinary unsealed template. */
    cap_t utempl = __builtin_cheri_tag_clear(obj);
    __asm__ volatile(
        "cbld   ca2, %[root], %[t]       \n\t"
        "gctag  %[tag], ca2              \n\t"
        : [tag]"=&r"(tag)
        : [root]"C"(root), [t]"C"(utempl)
        : "ca2");
    report(u, "T18 control: cbld rebuilds plain", tag, 1);
}


/* ========================================================================
 * T28 - SE/US in the permissions bitfield -- YPERMC and YPERMR.
 *
 * Spec 17.5: "The SE-permission and US-permission fields are mapped into the
 * capability permissions bitfield (Figure 6), used by YPERMC and YPERMR, as
 * shown in Figure 16."
 *
 * Figure 16 places  US at bit 25,  SE at bit 24,  and leaves 23:0 "as is".
 * Figure 6 makes bits XLEN-1:24 "Reserved 0" -- so SE/US come out of
 * reserved-ZERO space. That matters: bits 15:10 and 23:19 are Reserved ONE,
 * and a permission sited there would read as present on every capability.
 *
 * MNEMONICS: `gcperm` is YPERMR (read the permissions word) and `acperm` is
 * YPERMC (AND-mask it). acperm only ever CLEARS -- permissions are
 * monotonically non-increasing -- which T28h relies on.
 *
 * Nothing here uses yseal/yunseal; this is purely about the permission
 * plumbing being wired to the architectural bits the spec names.
 * ======================================================================== */
static void test_permission_bitfield(uart_t u, cap_t root)
{
    u64 p_root, p_both, p_se_only, p_us_only, p_neither, p_retry;

    put_str(u, "-- SE/US in the permissions bitfield (YPERMC/YPERMR) --\n");

    __asm__ volatile(
        "gcperm  %[pr], %[root]          \n\t"  /* YPERMR on the root   */

        "acperm  ca1, %[root], %[m_both] \n\t"  /* keep SE and US       */
        "gcperm  %[pb], ca1              \n\t"

        "acperm  ca2, %[root], %[m_se]   \n\t"  /* keep SE, drop US     */
        "gcperm  %[ps], ca2              \n\t"

        "acperm  ca3, %[root], %[m_us]   \n\t"  /* drop SE, keep US     */
        "gcperm  %[pu], ca3              \n\t"

        "acperm  ca4, %[root], %[m_none] \n\t"  /* drop both            */
        "gcperm  %[pn], ca4              \n\t"

        /* MONOTONICITY: ca4 has already lost SE/US.  Ask for them back. */
        "acperm  ca5, ca4, %[m_both]     \n\t"
        "gcperm  %[pt], ca5              \n\t"
        : [pr]"=&r"(p_root), [pb]"=&r"(p_both), [ps]"=&r"(p_se_only),
          [pu]"=&r"(p_us_only), [pn]"=&r"(p_neither), [pt]"=&r"(p_retry)
        : [root]"C"(root),
          [m_both]"r"(~0ULL),
          [m_se]"r"(~US),
          [m_us]"r"(~SE),
          [m_none]"r"(~(SE | US))
        : "ca1", "ca2", "ca3", "ca4", "ca5");

    /* The bit positions the spec names. */
    report(u, "T28a SE is permission bit 24            ", SE, 1ULL << 24);
    report(u, "T28b US is permission bit 25            ", US, 1ULL << 25);

    /* The root must carry both, else nothing could ever seal. */
    report(u, "T28c root has SE+US via gcperm          ",
           p_root & (SE | US), SE | US);

    /* acperm keeps them when asked. */
    report(u, "T28d acperm ~0 keeps both               ",
           p_both & (SE | US), SE | US);

    /* ...and drops them INDEPENDENTLY. */
    report(u, "T28e acperm ~US leaves SE only          ",
           p_se_only & (SE | US), SE);
    report(u, "T28f acperm ~SE leaves US only          ",
           p_us_only & (SE | US), US);
    report(u, "T28g acperm ~(SE|US) leaves neither     ",
           p_neither & (SE | US), 0);

    /* Monotonic: acperm is an AND, so a cleared permission stays cleared. */
    report(u, "T28h cleared SE/US cannot be restored   ",
           p_retry & (SE | US), 0);

    /* Figure 6 makes everything above bit 25 Reserved ZERO. */
    report(u, "T28i bits 26+ are Reserved-0 (all zero) ",
           p_root >> 26, 0);

    /* Dropping SE/US must not disturb any other permission. */
    report(u, "T28j clearing SE/US touches nothing else",
           p_neither, p_root & ~(SE | US));
}

/* ========================================================================
 * T29 - GL propagation through YUNSEAL -- spec 17.6.2.
 *
 *   "If the Zylevels1 extension is implemented, and the capability in rs1
 *    does not grant GL flag, use the semantics of the YPERMC instruction to
 *    clear the GL flag of the capability in rd."
 *
 * Stops a local authority laundering a capability back to global by unsealing
 * through it. 17.6.1 has no matching clause, so YSEAL must not do it -- T29g
 * is that control.
 *
 * Without Zylevels1 there is no GL flag  so T29a
 * detects the mode and the rest is skipped.
 * ======================================================================== */
static void test_gl_propagation(uart_t u, cap_t root, cap_t auth_gl)
{
    u64 p_probe, levels_on;

    put_str(u, "-- GL propagation through YUNSEAL (Zylevels1, 17.6.2) --\n");

    /*
     * Mode probe: acperm can only clear GL if Zylevels1 is on; otherwise
     * the encoding forces bit 4 back and the clear is ignored.
     */
    __asm__ volatile(
        "acperm  ca1, %[root], %[m_nogl] \n\t"
        "gcperm  %[p], ca1               \n\t"
        : [p]"=&r"(p_probe)
        : [root]"C"(root), [m_nogl]"r"(~GL)
        : "ca1");

    levels_on = (p_probe & GL) == 0;
    report(u, "T29a acperm can clear GL => Zylevels1 on", levels_on,
           levels_on);   /* always passes; prints the mode */

    if (!levels_on) {
        put_str(u, "       (Zylevels1 off --"
                   "T29b-h skipped)\n");
        return;
    }

    u64 t_glob, p_glob, t_loc, p_loc, p_sealed, p_ctl;

    __asm__ volatile(
        /* ---- the shared authority, demoted to local ------------- */
        "acperm  ca2, %[auth], %[m_nogl] \n\t"

        /* ---- the object to be sealed; keep it global ------------ */
        "scaddr  ca3, %[root], %[obj]    \n\t"
        "scbnds  ca3, ca3, %[len]        \n\t"
        "gcperm  %[psd], ca3             \n\t"  /* GL before sealing */

        /* ---- seal it with the GLOBAL authority ------------------ */
        "yseal   ca4, %[auth], ca3       \n\t"

        /* ---- unseal with the GLOBAL authority: GL must survive -- */
        "yunseal ca5, %[auth], ca4       \n\t"
        "gctag   %[tg], ca5              \n\t"
        "gcperm  %[pg], ca5              \n\t"

        /* ---- unseal with the LOCAL authority: GL must be gone --- */
        "yunseal ca6, ca2, ca4           \n\t"
        "gctag   %[tl], ca6              \n\t"
        "gcperm  %[pl], ca6              \n\t"

        /* ---- control: YSEAL through the LOCAL authority --------- */
        "yseal   ca7, ca2, ca3           \n\t"
        "gcperm  %[pc], ca7              \n\t"
        : [tg]"=&r"(t_glob), [pg]"=&r"(p_glob),
          [tl]"=&r"(t_loc),  [pl]"=&r"(p_loc),
          [psd]"=&r"(p_sealed), [pc]"=&r"(p_ctl)
        : [root]"C"(root), [auth]"C"(auth_gl),
          [obj]"r"((u64)(__UINTPTR_TYPE__)&g_buf[0]), [len]"r"(64ULL),
          [m_nogl]"r"(~GL)
        : "ca2", "ca3", "ca4", "ca5", "ca6", "ca7");

    /* The object must start global, else the rest proves nothing. */
    report(u, "T29b the object is global before sealing",
           p_sealed & GL, GL);

    report(u, "T29c global authority still unseals    ", t_glob, 1);
    report(u, "T29d ...and the result stays global    ",
           p_glob & GL, GL);

    /* Being local attenuates the result; it is not a refusal. */
    report(u, "T29e local authority unseals too       ", t_loc, 1);
    report(u, "T29f ...but the result loses GL        ",
           p_loc & GL, 0);

    report(u, "T29g YSEAL does NOT clear GL (control) ",
           p_ctl & GL, GL);
    report(u, "T29h GL is the only bit YUNSEAL touched",
           p_loc, p_glob & ~GL);
}

/* ======================================================================== */

void test_main(cap_t root, cap_t code_root)
{
    uart_t u = (uart_t)__builtin_cheri_bounds_set(
        __builtin_cheri_address_set(root, UART_BASE), 0x1000);

    put_str(u, "\n=== Zyseal: flat inline-assembly tests ===\n\n");

    /*
     * The object under test: a capability to g_buf, 64 bytes.
     * Built with plain C because it is not the thing being tested.
     */
    cap_t obj = __builtin_cheri_bounds_set((cap_t)&g_buf[0], sizeof(g_buf));
    cap_t slot = (cap_t)&g_slot;

    /*
     * The authorities, built once here rather than re-derived in every test.
     *
     *   auth     names type 2, entitled to [2,18), SE|US
     *   auth_gl  the same but keeps GL. acperm is an AND, so a bare SE|US mask
     *            leaves a LOCAL authority, and under Zylevels1 spec 17.6.2
     *            makes yunseal strip GL from whatever it opens.
     *   wide     entitled to [0,64), so any type number tested is IN BOUNDS
     *            and only the type-range check can reject it.
     *
     * Tests that need a DIFFERENT authority still build their own inline --
     * that is the thing under test in those cases, so it stays visible.
     */
    cap_t auth, auth_gl, wide;
    __asm__ volatile(
        "scaddr   %[a],  %[root], %[two]     \n\t"
        "scbndsr  %[a],  %[a],    %[sixteen] \n\t"
        "acperm   %[ag], %[a],    %[seusgl]  \n\t"
        "acperm   %[a],  %[a],    %[seus]    \n\t"
        "scaddr   %[w],  %[root], %[zero]    \n\t"
        "scbndsr  %[w],  %[w],    %[span]    \n\t"
        "acperm   %[w],  %[w],    %[seus]    \n\t"
        : [a]"=&C"(auth), [ag]"=&C"(auth_gl), [w]"=&C"(wide)
        : [root]"C"(root),
          [two]"r"(2ULL), [zero]"r"(0ULL),
          [sixteen]"r"(16ULL), [span]"r"(64ULL),
          [seus]"r"(SE | US), [seusgl]"r"(SE | US | GL));

    test_seal_sets_type_and_nothing_else(u, obj, auth, auth_gl);
    test_permissions_are_checked(u, obj, auth);
    test_authority_must_be_entitled(u, root, obj, auth);
    test_reserved_and_out_of_range_types(u, obj, wide);
    test_every_ct_value(u, obj, wide);
    test_sealed_capability_is_unusable(u, obj, auth);
    test_sealed_is_not_a_sentry(u, code_root, auth);
    test_type_survives_memory(u, obj, slot, auth);
    test_cbld_cannot_forge(u, root, obj, auth);
    test_permission_bitfield(u, root);
    test_gl_propagation(u, root, auth_gl);

    /* ---- summary ---- */
    put_ch(u, '\n');
    put_str(u, "RESULT: ");
    put_dec(u, (u64)g_pass);
    put_str(u, " passed, ");
    put_dec(u, (u64)g_fail);
    put_str(u, " failed -- ");
    put_str(u, g_fail == 0 ? "CLEAN\n" : "PROBLEMS\n");

    volatile u32 *__capability fin = (volatile u32 *__capability)
        __builtin_cheri_bounds_set(
            __builtin_cheri_address_set(root, TEST_BASE), 0x1000);
    *fin = g_fail == 0 ? 0x5555u : 0x3333u;

    for (;;) {
    }
}
