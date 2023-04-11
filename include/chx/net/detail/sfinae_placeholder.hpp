#pragma once

namespace chx::net::detail {
struct sfinae_t {
} constexpr static sfinae;
template <typename...> struct sfinae_placeholder {
    constexpr sfinae_placeholder(sfinae_t) noexcept(true) {}
};
}  // namespace chx::net::detail
