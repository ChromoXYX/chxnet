#pragma once

#include "./buffer.hpp"

#include <array>
#include <type_traits>
#include <sys/uio.h>

namespace chx::net {
namespace detail {
struct has_begin_and_end_impl {
    template <typename T, typename = decltype(std::declval<T>().begin()),
              typename = decltype(std::declval<T>().end())>
    has_begin_and_end_impl(T) {}
};

template <typename T, typename Target> struct is_buffer_sequence_impl {
    static auto f() {
        if constexpr (is_container<T>::value) {
            if constexpr (std::is_constructible_v<
                              Target, typename std::pointer_traits<
                                          decltype(std::declval<T>().data())>::
                                          element_type>) {
                return std::true_type{};
            } else {
                return std::false_type{};
            }
        } else {
            return std::false_type{};
        }
    }
    using type = decltype(f());
};

inline constexpr const struct iovec
to_iovec_const(const const_buffer& b) noexcept(true) {
    return {const_cast<void*>(b.data()), b.size()};
}
inline constexpr struct iovec
to_iovec_mutable(const mutable_buffer& b) noexcept(true) {
    return {b.data(), b.size()};
}
template <std::size_t... Is, typename T>
inline constexpr const std::array<const struct iovec, sizeof...(Is)>
generate_iovec_array_const(
    T&& a, std::integer_sequence<std::size_t, Is...>) noexcept(true) {
    return {to_iovec_const(const_buffer(a[Is]))...};
}
template <std::size_t... Is, typename T>
inline constexpr std::array<struct iovec, sizeof...(Is)>
generate_iovec_array_mutable(
    T&& a, std::integer_sequence<std::size_t, Is...>) noexcept(true) {
    return {to_iovec_mutable(mutable_buffer(a[Is]))...};
}
}  // namespace detail

/**
 * @brief Helper class to determine whether the type meets the requirements of
 * ConstBufferSequence.
 *
 */
template <typename T>
struct is_const_buffer_sequence
    : detail::is_buffer_sequence_impl<T, const_buffer>::type {
    constexpr static bool has_static_size = false;
};
/**
 * @brief Helper class to determine whether the type meets the requirements of
 * MutableBufferSequence.
 *
 */
template <typename T>
struct is_mutable_buffer_sequence
    : detail::is_buffer_sequence_impl<T, mutable_buffer>::type {
    constexpr static bool has_static_size = false;
};
/**
 * @brief Helper class to determine whether the type meets the requirements of
 * ConstBufferSequence.
 *
 */
template <typename T, std::size_t Size>
struct is_const_buffer_sequence<T[Size]>
    : std::is_constructible<const_buffer, T> {
    constexpr static bool has_static_size = true;
    constexpr static std::size_t static_size = Size;
};
/**
 * @brief Helper class to determine whether the type meets the requirements of
 * MutableBufferSequence.
 *
 */
template <typename T, std::size_t Size>
struct is_mutable_buffer_sequence<T[Size]>
    : std::is_constructible<mutable_buffer, T> {
    constexpr static bool has_static_size = true;
    constexpr static std::size_t static_size = Size;
};
/**
 * @brief Helper class to determine whether the type meets the requirements of
 * ConstBufferSequence.
 *
 */
template <typename T, std::size_t Size>
struct is_const_buffer_sequence<std::array<T, Size>>
    : std::is_constructible<const_buffer, T> {
    constexpr static bool has_static_size = true;
    constexpr static std::size_t static_size = Size;
};
/**
 * @brief Helper class to determine whether the type meets the requirements of
 * MutableBufferSequence.
 *
 */
template <typename T, std::size_t Size>
struct is_mutable_buffer_sequence<std::array<T, Size>>
    : std::is_constructible<mutable_buffer, T> {
    constexpr static bool has_static_size = true;
    constexpr static std::size_t static_size = Size;
};
}  // namespace chx::net
