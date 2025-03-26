#pragma once

#include <utility>

namespace chx::net {
template <typename T> struct binary_container {
    binary_container() = default;
    constexpr binary_container(T t) noexcept(true) : __M_data(std::move(t)) {}

    constexpr const void* data() const noexcept(true) { return &__M_data; }
    constexpr std::size_t size() const noexcept(true) {
        return sizeof(__M_data);
    }

  private:
    T __M_data;
};
}  // namespace chx::net
