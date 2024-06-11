#pragma once

#include "./buffer.hpp"
#include <cstddef>

namespace chx::net {
struct iovec_buffer : iovec {
    iovec_buffer() = default;
    constexpr iovec_buffer(const iovec_buffer&) = default;
    iovec_buffer(void* ptr, std::size_t len) noexcept(true) {
        iovec::iov_base = ptr;
        iovec::iov_len = len;
    }
    iovec_buffer(const_buffer buf) noexcept(true)
        : iovec_buffer((void*)buf.data(), buf.size()) {}

    using value_type = unsigned char;

    constexpr value_type* data() noexcept(true) {
        return static_cast<value_type*>(iovec::iov_base);
    }
    constexpr std::size_t size() const noexcept(true) { return iovec::iov_len; }
};
}  // namespace chx::net