// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

// allocator.hpp - the allocator core as one header: users of the core include
// this and nothing else from this directory. Adapted for SignetOS from these
// upstream files (sdk/core/allocator/), in the order the core needs them:
//
//   1. Configuration (alloc_config.h): 16-byte alignment, DEBUG_ALLOCATOR as
//      a 0/1 switch, no stack-usage checks, and the bit scans upstream takes
//      from <strings.h>.
//   2. The revoker (revoker.h): only `NoTemporalSafety`, with SignetOS's
//      revoker interface (`Revocation` below), and the choice of revoker.
//   -  The core itself: alloc.hpp (alloc.h).
//   3. From main.cc: the global `revoker`, and `mstate_init`, which no longer
//      carves a hazard quarantine out of the heap. The rest of main.cc is
//      CHERIoT's compartment interface.

#pragma once

#include <cheri.hpp>
#include <heap_compat.hpp>
#include <stddef.h>
#include <stdint.h>

/*
 * 1. Configuration (upstream: alloc_config.h)
 */

/**
 * 1 compiles in the allocator's consistency checks (the `ok_*` functions and
 * every `Debug::Assert`) and their messages.  They are slow: for debugging.
 */
#ifndef DEBUG_ALLOCATOR
#	define DEBUG_ALLOCATOR 0
#endif

using Debug = ConditionalDebug<DEBUG_ALLOCATOR, "Allocator">;

constexpr bool AllocatorDebugEnabled = DEBUG_ALLOCATOR;

#define ABORT()                                                                \
	Debug::Invariant(false, "Unrecoverable allocator corruption detected")

#ifdef NDEBUG
#	define RTCHECK(e) (1)
#else
#	define RTCHECK(e) (e)
constexpr size_t MStateSanityInterval = 128;
#endif

/*
 * A capability is 16 bytes on SignetOS (8 on CHERIoT) and must be stored
 * 16-byte aligned, so that is the alignment of every chunk.
 */
constexpr size_t MallocAlignShift = 4;

constexpr size_t MallocAlignment = 1U << MallocAlignShift;
constexpr size_t MallocAlignMask = MallocAlignment - 1;

/*
 * Count leading / trailing zero bits of a non-zero argument, at its own
 * width: a 64-bit `size_t` counts as 64 bits (upstream's take `uint32_t`).
 */
[[clang::always_inline]] constexpr size_t clz(unsigned int x)
{
	return __builtin_clz(x);
}
[[clang::always_inline]] constexpr size_t clz(unsigned long x)
{
	return __builtin_clzl(x);
}
[[clang::always_inline]] constexpr size_t ctz(unsigned int x)
{
	return __builtin_ctz(x);
}
[[clang::always_inline]] constexpr size_t ctz(unsigned long x)
{
	return __builtin_ctzl(x);
}

/*
 * 2. The revoker (upstream: revoker.h)
 */

/*
 * The revoker interface, as SignetOS changed it.  A revoker is a class with:
 *
 *   IsAsynchronous   a sweep runs in the background once kicked
 *   HasChunkMarks    it keeps shadow bits the allocator can read: mark_get()
 *                    answers, and mark_set_one(), mark_clear_one() and
 *                    mark_clear_range() keep the bit over each chunk header.
 *                    Without them those four do nothing, a chunk's header
 *                    is taken to be just before its body, and
 *                    MChunkHeader::isQuarantined tells freed from live.
 *   mark_set_range(range, epoch)
 *                    marks `range` for revocation and sets `epoch` to the
 *                    sweep that revokes it; false if it could not mark it.
 *                    (Upstream returns nothing; the allocator reads
 *                    system_epoch_get() instead.)
 *   has_revocation_finished_for_epoch(epoch), system_bg_revoker_kick()
 *                    as upstream.
 *
 * Epochs are `size_t`, 64 bits on SignetOS (upstream: 32).
 */
namespace Revocation
{
	/**
	 * Null implementation of the revoker interface.  Provides no temporal
	 * safety.
	 */
	class NoTemporalSafety
	{
		public:
		/**
		 * If there is no temporal memory safety, we treat sweeping as
		 * synchronous but infinitely fast which returns immediately.
		 */
		static constexpr bool IsAsynchronous = false;

		/// There are no shadow bits.
		static constexpr bool HasChunkMarks = false;

		void init() {}

		bool has_revocation_finished_for_epoch(size_t previousEpoch)
		{
			return true;
		}

		void system_bg_revoker_kick() {}

		bool mark_get(ptraddr_t addr)
		{
			Debug::Assert(false,
			              "shadow_bit_get should not be called on the revoker "
			              "with no temporal safety, its result is meaningless");
			return false;
		}

		void mark_set_one(CHERI::Capability<void>) {}

		void mark_clear_one(ptraddr_t) {}

		/// Marks nothing; the epoch is always 0, which has always finished.
		bool mark_set_range(CHERI::Capability<void>, size_t &epoch)
		{
			epoch = 0;
			return true;
		}

		void mark_clear_range(size_t, size_t) {}
	};

	/**
	 * The revoker to use for this configuration: the class named by
	 * ALLOCATOR_REVOKER, if whoever includes this file has defined one
	 * (user/heap.hpp defines SignetOS's), and otherwise none.
	 */
#ifdef ALLOCATOR_REVOKER
	using Revoker = ALLOCATOR_REVOKER;
#else
	using Revoker = NoTemporalSafety;
#endif
} // namespace Revocation

/*
 * The core (upstream: alloc.h)
 */

#include "alloc.hpp"

/*
 * 3. mstate_init (upstream: main.cc)
 */

/*
 * `inline`: this header may be included by several files of an image.
 * `constinit`: compartments run no constructors.
 */
inline constinit Revocation::Revoker revoker;

/**
 * @brief Take a memory region and initialise a memory space for it. The
 * MState structure will be placed at the beginning and the rest used as the
 * real heap.
 *
 * The region must be zeroed: the bins, the bin maps and the size counters of
 * the MState are taken to be zero, as is every byte that is later handed out.
 *
 * @param tbase the capability to the region
 * @param tsize size of the region
 * @return pointer to the MState if can be initialised, nullptr otherwise.
 */
inline MState *mstate_init(Capability<void> tbase, size_t tsize)
{
	if (!is_aligned(tbase) || !is_aligned(tsize))
	{
		return nullptr;
	}

	size_t msize = pad_request(sizeof(MState));

	/*
	 * Each memory space has the MState structure at the beginning,
	 * then at least enough space for a smallest chunk, and a fake
	 * malloc header at the very end.
	 *
	 * The memory used to initialise a memory space must have enough bytes,
	 * but not too big that overflows what the compressed header can
	 * support.
	 */
	if (tsize < (msize + MinChunkSize + sizeof(MChunkHeader)) ||
	    tsize > MaxChunkSize)
	{
		return nullptr;
	}

	Capability m{tbase.cast<MState>()};

	m.bounds()            = sizeof(*m);
	m->heapStart          = tbase;
	m->heapStart.bounds() = tsize;
	/*
	 * The address of the start of the heap must be 16-byte aligned,
	 * but we do not need to pad here: we already did when
	 * calculating msize.
	 */
	m->heapStart.address() += msize;
	m->init_bins();

	m->mspace_firstchunk_add(ds::pointer::offset<void>(tbase.get(), msize),
	                         tsize - msize);

	return m;
}
