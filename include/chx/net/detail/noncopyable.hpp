#pragma once

namespace chx::net::detail {
template <int Counter> struct noncopyable {
    noncopyable() = default;
    noncopyable(const noncopyable&) = delete;
    noncopyable(noncopyable&&) = default;

    noncopyable& operator=(const noncopyable&) = delete;
    noncopyable& operator=(noncopyable&&) = default;
};

#define CHXNET_NONCOPYABLE ::chx::net::detail::noncopyable<__COUNTER__>
}  // namespace chx::net::detail