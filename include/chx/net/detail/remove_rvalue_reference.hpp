#pragma once

#include <utility>

namespace chx::net::detail {
template <typename T> constexpr T remove_rvalue_reference_impl(T&&);

template <typename T> struct remove_rvalue_reference {
    using type = decltype(remove_rvalue_reference_impl(std::declval<T>()));
};
}  // namespace chx::net::detail