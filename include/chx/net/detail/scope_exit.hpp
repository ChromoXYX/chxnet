#pragma once

#include <utility>

namespace chx::net::detail {
template <typename Fn> struct scope_exit : Fn {
    constexpr scope_exit(Fn&& fn) : Fn(std::move(fn)) {}
    ~scope_exit() { Fn::operator()(); }
};
}  // namespace chx::net::detail
