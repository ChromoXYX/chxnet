#pragma once

#include "./buffer.hpp"
#include <cstddef>

namespace chx::net {
struct iovec_buffer : iovec {
    iovec_buffer() noexcept(true) {
        iovec::iov_base = nullptr;
        iovec::iov_len = 0;
    }
    iovec_buffer(const iovec_buffer&) = default;
    iovec_buffer(void* ptr, std::size_t len) noexcept(true) {
        iovec::iov_base = ptr;
        iovec::iov_len = len;
    }
    iovec_buffer(const_buffer buf) noexcept(true)
        : iovec_buffer((void*)buf.data(), buf.size()) {}

    using value_type = unsigned char;

    value_type* data() noexcept(true) {
        return static_cast<value_type*>(iovec::iov_base);
    }
    std::size_t size() const noexcept(true) { return iovec::iov_len; }
};
}  // namespace chx::net