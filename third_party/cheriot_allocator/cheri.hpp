// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

// Cut down for SignetOS from sdk/include/cheri.hh: the representability
// helpers and the parts of `Capability` the allocator and ds/ use, with
// upstream's semantics.  No permissions, sealing, `check_pointer` or
// exception cause codes, so `Capability` has no `IsSealed` parameter.

#pragma once
/**
 * \file
 * \brief C++ helpers for operating on capabilities.
 */
#include <heap_compat.hpp>
#include <stdint.h>

namespace CHERI
{
	/**
	 * Rounds `len` up to a CHERI representable length for the current
	 * architecture.
	 */
	__always_inline inline size_t representable_length(size_t length)
	{
		return __builtin_cheri_round_representable_length(length);
	}

	/**
	 * Returns the alignment mask required for a given length.
	 */
	__always_inline inline size_t representable_alignment_mask(size_t length)
	{
		return __builtin_cheri_representable_alignment_mask(length);
	}

	/// Can the range [base, base + size) be precisely covered by a capability?
	inline bool is_precise_range(ptraddr_t base, size_t size)
	{
		return (base & ~representable_alignment_mask(size)) == 0 &&
		       representable_length(size) == size;
	}

	/**
	 * Helper class for accessing capability properties on pointers.
	 */
	template<typename T>
	class Capability
	{
		protected:
		/// The capability that this class wraps.
		T *ptr;

		private:
		/**
		 * Base class for the proxies that accessors in this class return.
		 */
		class PropertyProxyBase
		{
			protected:
			/**
			 * The capability that this proxy refers to.
			 */
			Capability &cap;

			/**
			 * Replaces the underlying capability
			 */
			template<typename U>
			void set(U *newPtr)
			{
				cap.ptr = static_cast<T *>(newPtr);
			}

			/**
			 * Returns the capability's pointer.
			 */
			[[nodiscard]] auto ptr() const
			{
				return cap.ptr;
			}

			public:
			/// Constructor, takes the capability whose property this class is
			/// proxying.
			PropertyProxyBase(Capability &c) : cap(c) {}
		};

		/**
		 * Proxy for accessing a capability's address.
		 */
		struct AddressProxy : public PropertyProxyBase
		{
			/// Inherit the constructor from the base class.
			using PropertyProxyBase::PropertyProxyBase;
			/// Inherit the pointer accesors
			/// @{
			using PropertyProxyBase::ptr;
			using PropertyProxyBase::set;
			/// @}

			/**
			 * Implicit casts can convert this to an address.
			 */
			operator ptraddr_t() const
			{
				return __builtin_cheri_address_get(ptr());
			}

			/**
			 * Set the address in the underlying capability.
			 */
			AddressProxy &operator=(ptraddr_t addr)
			{
				set(__builtin_cheri_address_set(ptr(), addr));
				return *this;
			}

			/**
			 * Set the address in the underlying capability given another
			 * address proxy.
			 */
			AddressProxy &operator=(AddressProxy addr)
			{
				set(__builtin_cheri_address_set(ptr(), addr));
				return *this;
			}

			/**
			 * Add a displacement to the capability's address.
			 */
			AddressProxy &operator+=(ptrdiff_t displacement)
			{
				set(__builtin_cheri_offset_increment(ptr(), displacement));
				return *this;
			}

			/**
			 * Subtract a displacement from the capability's address.
			 */
			AddressProxy &operator-=(ptrdiff_t displacement)
			{
				set(__builtin_cheri_offset_increment(ptr(), -displacement));
				return *this;
			}
		};

		/**
		 * Proxy for accessing an object's bounds.
		 */
		struct BoundsProxy : public PropertyProxyBase
		{
			/// Inherit the constructor from the base class.
			using PropertyProxyBase::PropertyProxyBase;
			/// Inherit the pointer accesors
			/// @{
			using PropertyProxyBase::ptr;
			using PropertyProxyBase::set;
			/// @}

			/**
			 * Return the object's bounds (displacement from the address to the
			 * end).
			 */
			operator ptrdiff_t() const
			{
#if __has_builtin(__builtin_cheri_top_get)
				return __builtin_cheri_top_get(ptr()) -
				       __builtin_cheri_address_get(ptr());
#else
				return __builtin_cheri_length_get(ptr()) -
				       (__builtin_cheri_address_get(ptr()) -
				        __builtin_cheri_base_get(ptr()));
#endif
			}

			/**
			 * Set the capability's bounds, giving an invalid capability if this
			 * cannot be represented exactly.
			 */
			BoundsProxy &operator=(size_t bounds)
			{
				set(__builtin_cheri_bounds_set_exact(ptr(), bounds));
				return *this;
			}
		};

		/// The property proxy base is allowed to directly access the pointer
		/// that this class wraps.
		friend class PropertyProxyBase;

		public:
		/// Constructor from a null pointer.
		constexpr Capability(std::nullptr_t) : ptr(nullptr) {}
		/// Default constructor, initialises with a null pointer.
		constexpr Capability() : ptr(nullptr) {}
		/// Constructor, takes an existing pointer to wrap
		constexpr Capability(decltype(ptr) p) : ptr(p) {}
		/// Copy constructor, aliases the object that is pointed to by `ptr`.
		constexpr Capability(const Capability &other) = default;

		/**
		 * Replace the pointer that this capability wraps with another.
		 */
		Capability &operator=(const Capability &other) = default;

		/**
		 * Access the address of the capability.
		 */
		AddressProxy address() [[clang::lifetimebound]]
		{
			return {*this};
		}

		/**
		 * Return the address as an integer from a `const` capability.
		 */
		[[nodiscard]] ptraddr_t address() const
		{
			return __builtin_cheri_address_get(ptr);
		}

		/**
		 * Access (read, set) the capability's bounds.
		 */
		BoundsProxy bounds() [[clang::lifetimebound]]
		{
			return {*this};
		}

		/**
		 * Return the bounds as an integer.
		 */
		[[nodiscard]] __always_inline ptrdiff_t bounds() const
		{
			return top() - address();
		}

		/**
		 * Returns the tag bit indicating whether this is a valid
		 * capability.
		 */
		[[nodiscard]] bool is_valid() const
		{
			return __builtin_cheri_tag_get(ptr);
		}

		/**
		 * Return whether this is a sealed capability.
		 */
		[[nodiscard]] bool is_sealed() const
		{
			return __builtin_cheri_type_get(ptr) != 0;
		}

		/**
		 * Returns the base address of this capability.
		 */
		[[nodiscard]] ptraddr_t base() const
		{
			return __builtin_cheri_base_get(ptr);
		}

		/**
		 * Returns the length of this capability.
		 */
		[[nodiscard]] size_t length() const
		{
			return __builtin_cheri_length_get(ptr);
		}

		/**
		 * Returns the address of the top of this capability.
		 */
		[[nodiscard]] ptraddr_t top() const
		{
#if __has_builtin(__builtin_cheri_top_get)
			return __builtin_cheri_top_get(ptr);
#else
			return base() + length();
#endif
		}

		constexpr bool operator==(const Capability Other) const
		{
			return __builtin_cheri_equal_exact(ptr, Other.ptr);
		}

		/**
		 * Comparison against null pointer.
		 *
		 * Returns true if this is a canonical null pointer, false for any
		 * other (tagged or untagged) value.  Callers may often want
		 * `is_valid` instead of this.
		 */
		constexpr bool operator==(std::nullptr_t) const
		{
			return __builtin_cheri_equal_exact(ptr, nullptr);
		}

		/**
		 * Implicit cast to the raw pointer type.
		 */
		template<typename U = T>
		    requires(!std::same_as<U, void>)
		operator U *() const
		{
			return ptr;
		}

		/**
		 * Implicit cast to a raw pointer type.
		 */
		operator void *() const
		{
			return ptr;
		}

		/**
		 * Access fields of the target as if this were a raw pointer.
		 */
		T *operator->() const
		{
			return ptr;
		}

		/**
		 * Explicitly get the raw pointer.
		 */
		[[nodiscard]] T *get() const
		{
			return ptr;
		}

		/**
		 * Dereference operator.
		 */
		template<typename U = T>
		    requires(!std::same_as<U, void>)
		U &operator*() const
		{
			return *ptr;
		}

		/**
		 * Cast this capability to some other type.
		 */
		template<typename U>
		[[nodiscard]] Capability<U> cast() const
		{
			return {static_cast<U *>(ptr)};
		}

		/**
		 * Returns true if the tags of `this` and `other` match and if `this`
		 * conveys no rights that are not present in `other`.  Returns false in
		 * all other cases.
		 */
		template<typename U>
		[[nodiscard]] bool is_subset_of(Capability<U> other) const
		{
			return __builtin_cheri_subset_test(other.ptr, ptr);
		}
	};

	template<typename T>
	Capability(T *) -> Capability<T>;
} // namespace CHERI
