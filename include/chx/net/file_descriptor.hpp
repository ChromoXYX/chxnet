#pragma once

#include "./io_context.hpp"
#include "./buffer.hpp"
#include "detail/sfinae_placeholder.hpp"

namespace chx::net {
class file_descriptor : CHXNET_NONCOPYABLE {
    template <typename> friend struct detail::async_operation;

    io_context* __M_ctx;
    int __M_fd = -1;

  public:
    constexpr file_descriptor(io_context& ctx, int fd = -1) noexcept(true)
        : __M_ctx(&ctx), __M_fd(fd) {}
    file_descriptor(file_descriptor&& other) noexcept(true)
        : __M_ctx(other.__M_ctx), __M_fd(std::exchange(other.__M_fd, -1)) {}

    constexpr file_descriptor&
    operator=(file_descriptor&& other) noexcept(true) {
        if (this == &other) {
            return *this;
        }
        __M_ctx = other.__M_ctx;
        __M_fd = std::exchange(other.__M_fd, -1);
        return *this;
    }

    ~file_descriptor() noexcept(true) {
        if (is_open()) {
            close();
        }
    }

    constexpr io_context& get_associated_io_context() noexcept(true) {
        return *__M_ctx;
    }
    constexpr int native_handler() const noexcept(true) { return __M_fd; }
    constexpr void release() noexcept(true) { __M_fd = -1; }
    constexpr void set_fd(int new_fd) noexcept(true) { __M_fd = new_fd; }

    bool is_open() const noexcept(true) {
        return native_handler() > 0 &&
               (::fcntl(native_handler(), F_GETFD) || errno != EBADF);
    }
    int close() noexcept(true) { return ::close(native_handler()); }

    template <typename MutableBuffer, typename CompletionToken>
    decltype(auto) async_read_some(
        MutableBuffer&& mutable_buffer, CompletionToken&& completion_token,
        detail::sfinae_placeholder<
            std::enable_if_t<detail::is_mutable_buffer<MutableBuffer>::value>>
            _ = net::detail::sfinae);
    template <typename ConstBuffer, typename CompletionToken>
    decltype(auto) async_write_some(
        ConstBuffer&& const_buffer, CompletionToken&& completion_token,
        detail::sfinae_placeholder<
            std::enable_if_t<detail::is_const_buffer<ConstBuffer>::value>>
            _ = net::detail::sfinae);
};
}  // namespace chx::net

#include "./impl/file_descriptor.ipp"
