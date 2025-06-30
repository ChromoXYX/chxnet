#pragma once

#include <cstddef>
#include <cstdlib>
#include <memory>
#include <type_traits>
#include <utility>

namespace chx::net::detail {
struct ref_buffer_header {
    std::size_t owner_count = 0;
};

template <typename T, typename Allocator> class ref_buffer_base : Allocator {
    static_assert(std::is_trivial<ref_buffer_header>::value);

    std::size_t __M_size = 0;
    union {
        ref_buffer_header* __M_impl = nullptr;
        T* __M_t_ptr;
    };

    static inline constexpr std::size_t header_n_aligned =
        (sizeof(ref_buffer_header) + sizeof(T) - 1) / sizeof(T);

    constexpr std::size_t byte_size() const noexcept(true) {
        return sizeof(T) * (header_n_aligned + __M_size);
    }

  public:
    using value_type = T;
    using allocator_type = Allocator;
    using reference = T&;
    using const_reference = const T&;
    using pointer = T*;
    using const_pointer = const T*;

    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;

    ~ref_buffer_base() { release(); }

    ref_buffer_base(std::size_t n,
                    const allocator_type& alloc = allocator_type())
        : Allocator(alloc), __M_size(n) {
        (new (__M_t_ptr = Allocator::allocate(header_n_aligned + n))
             ref_buffer_header)
            ->owner_count = 1;
    }
    constexpr ref_buffer_base(const ref_buffer_base& other) noexcept(true)
        : __M_size(other.__M_size), __M_impl(other.__M_impl) {
        if (__M_impl) {
            ++__M_impl->owner_count;
        }
    }
    constexpr ref_buffer_base(ref_buffer_base&& other) noexcept(true)
        : __M_size(std::exchange(other.__M_size, 0)),
          __M_impl(std::exchange(other.__M_impl, nullptr)) {}

    constexpr ref_buffer_base& operator=(const ref_buffer_base& other) {
        if (this == &other) {
            return *this;
        }
        release();
        __M_size = other.__M_size;
        __M_impl = other.__M_impl;
        if (__M_impl) {
            ++__M_impl->owner_count;
        }
        return *this;
    }
    constexpr ref_buffer_base& operator=(ref_buffer_base&& other) {
        if (this == &other) {
            return *this;
        }
        release();
        __M_size = std::exchange(other.__M_size, 0);
        __M_impl = std::exchange(other.__M_impl, nullptr);
        return *this;
    }

    constexpr pointer data() noexcept(true) {
        return __M_t_ptr + header_n_aligned;
    }
    constexpr const_pointer data() const noexcept(true) {
        return __M_t_ptr + header_n_aligned;
    }
    constexpr size_type size() const noexcept(true) { return __M_size; }

    void release() {
        if (__M_impl && !--__M_impl->owner_count) {
            Allocator::deallocate(__M_t_ptr, header_n_aligned + size());
        }
    }
};

template <typename T, typename Allocator = std::allocator<T>>
class ref_buffer : public ref_buffer_base<T, Allocator> {
    std::size_t __M_offset = 0;
    std::size_t __M_size = 0;

    using typename ref_buffer_base<T, Allocator>::allocator_type;
    using typename ref_buffer_base<T, Allocator>::pointer;
    using typename ref_buffer_base<T, Allocator>::const_pointer;
    using typename ref_buffer_base<T, Allocator>::size_type;

  public:
    ref_buffer(std::size_t n, const allocator_type& alloc = allocator_type())
        : ref_buffer_base<T, Allocator>(n, alloc) {}
    ref_buffer(const ref_buffer_base<T, Allocator>& buf)
        : ref_buffer_base<T, Allocator>(buf), __M_offset(0),
          __M_size(buf.size()) {}
    ref_buffer(const ref_buffer& other) noexcept(true)
        : ref_buffer_base<T, Allocator>(other), __M_offset(other.__M_offset),
          __M_size(other.__M_size) {}
    ref_buffer(ref_buffer&& other) noexcept(true)
        : ref_buffer_base<T, Allocator>(
              static_cast<ref_buffer_base<T, Allocator>&&>(other)),
          __M_offset(std::exchange(other.__M_offset, 0)),
          __M_size(std::exchange(other.__M_size, 0)) {}

    constexpr ref_buffer& operator=(const ref_buffer& other) {
        if (this == &other) {
            return *this;
        }
        ref_buffer_base<T, Allocator>::operator=(other);
        __M_offset = other.__M_offset;
        __M_size = other.__M_size;
        return *this;
    }

    constexpr ref_buffer& operator=(ref_buffer&& other) {
        if (this == &other) {
            return *this;
        }
        ref_buffer_base<T, Allocator>::operator=(std::move(other));
        __M_offset = std::exchange(other.__M_offset, 0);
        __M_size = std::exchange(other.__M_size, 0);
        return *this;
    }

    constexpr pointer data() noexcept(true) {
        return ref_buffer_base<T, Allocator>::data() + __M_offset;
    }
    constexpr const_pointer data() const noexcept(true) {
        return ref_buffer_base<T, Allocator>::data() + __M_offset;
    }
    constexpr size_type size() const noexcept(true) { return __M_size; }

    constexpr ref_buffer sub_buffer(size_type offset, size_type count) const
        noexcept(true) {
        ref_buffer result(*this);
        result.__M_offset = __M_offset + offset;
        result.__M_size = count;
        return result;
    }
};
}  // namespace chx::net::detail
