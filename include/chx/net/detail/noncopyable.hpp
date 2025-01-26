#pragma once

namespace chx::net::detail {
struct noncopyable {
    noncopyable() = default;
    noncopyable(const noncopyable&) = delete;
    noncopyable(noncopyable&&) = default;

    noncopyable& operator=(const noncopyable&) = delete;
    noncopyable& operator=(noncopyable&&) = default;
};

struct nonmoveable {
    nonmoveable() = default;
    nonmoveable(const nonmoveable&) = default;
    nonmoveable(nonmoveable&&) = delete;

    nonmoveable& operator=(const nonmoveable&) = default;
    nonmoveable& operator=(nonmoveable&&) = delete;
};

#define CHXNET_NONCOPYABLE ::chx::net::detail::noncopyable __noncopyable[0];
#define CHXNET_NONMOVEABLE ::chx::net::detail::nonmoveable __nonmoveable[0];
}  // namespace chx::net::detail
