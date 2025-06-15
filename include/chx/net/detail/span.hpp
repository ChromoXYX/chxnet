#pragma once

#include <cstddef>
#include <iterator>

#include "../type_traits/is_container.hpp"

namespace chx::net::detail {
template <typename T> struct span {
    template <typename Contianer>
    constexpr span(Contianer&& container) noexcept(
        noexcept(std::data(container)) && noexcept(std::size(container)))
        : __M_ptr(std::data(container)), __M_n(std::size(container)) {}
    constexpr span(T* t, std::size_t s) noexcept(true) : __M_ptr(t), __M_n(s) {}

    constexpr span& operator=(const span& other) noexcept(true) = default;

    constexpr std::size_t size() const noexcept(true) { return __M_n; }
    constexpr T* data() noexcept(true) { return __M_ptr; }
    constexpr const T* data() const noexcept(true) { return __M_ptr; }

  private:
    T* __M_ptr = nullptr;
    std::size_t __M_n = 0;
};
template <typename Container>
span(Container&&) -> span<typename is_container<Container&&>::value_type>;
}  // namespace chx::net::detail
