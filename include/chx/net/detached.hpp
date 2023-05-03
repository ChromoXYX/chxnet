#pragma once

namespace chx::net {
struct detached_t {
    template <typename... Ts>
    constexpr void operator()(Ts&&... ts) noexcept(true) {}
};

constexpr inline detached_t detached = {};
}  // namespace chx::net
