#pragma once

namespace chx::net::detail {
template <typename T, T Value> struct integral_constant {
    constexpr inline static T value = Value;
};
}  // namespace chx::net::detail
