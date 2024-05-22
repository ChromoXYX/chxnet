#pragma once

#include "./buffer.hpp"
#include <cstddef>

namespace chx::net {
struct iovec_buffer : iovec {
    constexpr iovec_buffer() = default;
    constexpr iovec_buffer(const iovec_buffer&) = default;
    constexpr iovec_buffer(void* ptr, std::size_t len) noexcept(true) {
        iovec::iov_base = ptr;
        iovec::iov_len = len;
    }
    iovec_buffer(const_buffer buf) noexcept(true)
        : iovec_buffer((void*)buf.data(), buf.size()) {}

    using value_type = void*;

    constexpr void* data() noexcept(true) { return iovec::iov_base; }
    constexpr std::size_t size() const noexcept(true) { return iovec::iov_len; }
};
}  // namespace chx::net