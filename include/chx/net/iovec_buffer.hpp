#pragma once

#include <bits/types/struct_iovec.h>
#include <cstddef>

namespace chx::net {
struct iovec_buffer : iovec {
    constexpr iovec_buffer() = default;
    constexpr iovec_buffer(const iovec_buffer&) = default;
    constexpr iovec_buffer(void* ptr, std::size_t len) noexcept(true) {
        iovec::iov_base = ptr;
        iovec::iov_len = len;
    }

    using value_type = void*;

    constexpr void* data() noexcept(true) { return iovec::iov_base; }
    constexpr std::size_t size() const noexcept(true) { return iovec::iov_len; }
};
}  // namespace chx::net