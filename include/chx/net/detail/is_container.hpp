#pragma once

#include <type_traits>

namespace chx::net::detail {
template <typename T, typename = void> struct is_container : std::false_type {};
template <typename T>
struct is_container<T, std::void_t<decltype(std::declval<T>().data()),
                                   decltype(std::declval<T>().size())>>
    : std::true_type {};

template <typename T, typename = void>
struct has_begin_end : std::false_type {};
template <typename T>
struct has_begin_end<T, std::void_t<decltype(std::declval<T>().begin()),
                                    decltype(std::declval<T>().end())>>
    : std::true_type {};
}  // namespace chx::net::detail
