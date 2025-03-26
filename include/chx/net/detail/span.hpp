#pragma once

#include <cstddef>

namespace chx::net::detail {
template <typename T> struct span {
    constexpr span(T* t, std::size_t s) noexcept(true) : ptr(t), n(s) {}

    T* ptr = nullptr;
    std::size_t n = 0;

    constexpr std::size_t size() const noexcept(true) { return n; }
    constexpr T* data() noexcept(true) { return ptr; }
    constexpr const T* data() const noexcept(true) { return ptr; }
};
}  // namespace chx::net::detail
