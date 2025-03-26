#pragma once

#include <utility>

namespace chx::net::detail {
template <typename T> struct type_identity {
    using type = T;

    constexpr T& operator()(T& t) const noexcept(true) { return t; }
    constexpr T* operator()(T* t) const noexcept(true) { return t; }

    constexpr T* cast(void* p) const noexcept(true) {
        return static_cast<T*>(p);
    }
};
template <typename T> struct type_identity<T&> {
    using type = T&;

    constexpr T& operator()(T& t) const noexcept(true) { return t; }
};
template <typename T> struct type_identity<T&&> {
    using type = T&&;

    constexpr T&& operator()(T&& t) const noexcept(true) {
        return std::move(t);
    }
};
template <> struct type_identity<void> {
    using type = void;
};
}  // namespace chx::net::detail
