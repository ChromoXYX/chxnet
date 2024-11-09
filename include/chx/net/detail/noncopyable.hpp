#pragma once

#include <type_traits>

namespace chx::net::detail {
struct noncopyable {
    noncopyable() = default;
    noncopyable(const noncopyable&) = delete;
    noncopyable(noncopyable&&) = default;

    noncopyable& operator=(const noncopyable&) = delete;
    noncopyable& operator=(noncopyable&&) = default;

  private:
    struct noncopyable_test;
    struct noncopyable_check;
};
struct noncopyable::noncopyable_test {
    noncopyable_test() = default;
    noncopyable_test(noncopyable_test&&) = default;

    noncopyable_test& operator=(noncopyable_test&&) = default;

    noncopyable __noncopyable[0];
};
struct noncopyable::noncopyable_check {
    static_assert(!std::is_copy_constructible_v<noncopyable_test> &&
                  !std::is_copy_assignable_v<noncopyable_test>);
};

#define CHXNET_NONCOPYABLE ::chx::net::detail::noncopyable __noncopyable[0];
}  // namespace chx::net::detail
