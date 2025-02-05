#pragma once

#include <netinet/in.h>

#include "./io_context.hpp"
#include "./impl/general_async_close.hpp"
#include "./impl/general_io.hpp"

#include "./detail/io_uring_task_getter.hpp"

namespace chx::net::detail::tags {
struct cancel_fd {};
struct sock_poll {};
}  // namespace chx::net::detail::tags

template <>
struct chx::net::detail::async_operation<::chx::net::detail::tags::cancel_fd> {
    void operator()(io_context* ctx, int fd) const {
        auto* sqe = ctx->get_sqe();
        io_uring_prep_cancel_fd(sqe, fd, IORING_ASYNC_CANCEL_ALL);
        io_uring_sqe_set_data(sqe, nullptr);
        sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
        ctx->submit();
    }
};

template <>
struct chx::net::detail::async_operation<chx::net::detail::tags::sock_poll> {
    template <typename Sock, typename CompletionToken>
    decltype(auto) operator()(io_context*, Sock&, int, CompletionToken&&);

    template <typename Sock, typename BindCompletionToken>
    decltype(auto) multi(io_context*, Sock&, int, BindCompletionToken&&);
};

namespace chx::net {
class stream_base {
    template <typename Tag> friend struct detail::async_operation;

  protected:
    const io_context* __M_ctx = nullptr;
    int __M_fd = -1;

  public:
    constexpr stream_base(io_context& ctx) noexcept(true) : __M_ctx(&ctx) {}
    constexpr stream_base(io_context& ctx, int fd) noexcept(true)
        : __M_ctx(&ctx), __M_fd(fd) {}
    stream_base(stream_base&& other) noexcept(true)
        : __M_ctx(other.__M_ctx), __M_fd(std::exchange(other.__M_fd, -1)) {}

    stream_base& operator=(stream_base&& other) noexcept(true) {
        if (this == &other) {
            return *this;
        }
        __M_ctx = other.__M_ctx;
        __M_fd = std::exchange(other.__M_fd, __M_fd);
        return *this;
    }

    ~stream_base() {
        if (is_open()) {
            std::error_code ec;
            // cancel();
            close(ec);
        }
    }

    constexpr int native_handler() const noexcept(true) { return __M_fd; }
    constexpr io_context& get_associated_io_context() const noexcept(true) {
        return const_cast<io_context&>(*__M_ctx);
    }

    bool is_open() const noexcept(true) {
        return native_handler() > 0 &&
               (::fcntl(native_handler(), F_GETFD) || errno != EBADF);
    }

    void set_option(int level, int name, bool value,
                    std::error_code& ec) noexcept(true) {
        int v = value ? 1 : 0;
        if (::setsockopt(__M_fd, level, name, &v, sizeof(v)) == 0) {
            ec.clear();
        } else {
            net::assign_ec(ec, errno);
        }
    }

    void set_option(int level, int name, int value,
                    std::error_code& ec) noexcept(true) {
        if (::setsockopt(__M_fd, level, name, &value, sizeof(value)) == 0) {
            ec.clear();
        } else {
            net::assign_ec(ec, errno);
        }
    }

    void set_option(int level, int name, bool value) {
        std::error_code ec;
        set_option(level, name, value, ec);
        if (ec) {
            __CHXNET_THROW_EC(ec);
        }
    }

    void set_option(int level, int name, int value) {
        std::error_code ec;
        set_option(level, name, value, ec);
        if (ec) {
            __CHXNET_THROW_EC(ec);
        }
    }

    template <typename CharT, std::size_t N,
              typename = std::enable_if_t<sizeof(CharT) == 1>>
    void set_option(int level, int name, const CharT (&p)[N],
                    std::error_code& e) noexcept(true) {
        if (::setsockopt(__M_fd, level, name, p, N) == 0) {
            e.clear();
        } else {
            net::assign_ec(e, errno);
        }
    }

    template <typename CharT, std::size_t N,
              typename = std::enable_if_t<sizeof(CharT) == 1>>
    void set_option(int level, int name, const CharT (&p)[N]) {
        std::error_code ec;
        set_option(level, name, std::forward<const CharT(&)[N]>(p), ec);
        if (ec) {
            __CHXNET_THROW_EC(ec);
        }
    }

    void close() {
        std::error_code ec;
        close(ec);
        if (ec) {
            __CHXNET_THROW_EC(ec);
        }
    }

    void close(std::error_code& ec) noexcept(true) {
        if (::close(__M_fd) == -1) {
            net::assign_ec(ec, errno);
        } else {
            ec.clear();
        }
        __M_fd = -1;
    }

    constexpr void release() noexcept(true) { __M_fd = -1; }

    void cancel() {
        net::detail::async_operation<detail::tags::cancel_fd>()(
            &get_associated_io_context(), native_handler());
    }

    enum shutdown_type : int {
        shutdown_receive = SHUT_RD,
        shutdown_write = SHUT_WR,
        shutdown_both = SHUT_RDWR
    };

    void shutdown(shutdown_type how) {
        if (::shutdown(__M_fd, how) == 0) {
            return;
        } else {
            __CHXNET_THROW(errno);
        }
    }

    void shutdown(shutdown_type how, std::error_code& ec) noexcept(true) {
        if (is_open()) {
            if (::shutdown(__M_fd, how) == 0) {
                ec.clear();
            } else {
                net::assign_ec(ec, errno);
            }
        }
    }

    template <typename CompletionToken>
    decltype(auto) async_close(CompletionToken&& completion_token) {
        return detail::async_operation<detail::tags::async_close>()(
            &get_associated_io_context(), this,
            detail::async_token_bind<const std::error_code&>(
                std::forward<CompletionToken>(completion_token)));
    }

    template <typename CompletionToken>
    decltype(auto) async_poll(int event, CompletionToken&& completion_token);

    template <typename CompletionToken>
    decltype(auto) async_poll_multi(int event,
                                    CompletionToken&& completion_token);

    template <typename ConstBufferSequence, typename CompletionToken>
    decltype(auto) async_write_some(
        ConstBufferSequence&& const_buffer_sequence,
        CompletionToken&& completion_token,
        net::detail::sfinae_placeholder<
            std::enable_if_t<is_const_buffer_sequence<
                std::remove_reference_t<ConstBufferSequence>>::value>>
            _ = net::detail::sfinae) {
        return net::detail::async_operation<net::detail::tags::writev>()(
            &get_associated_io_context(), this,
            std::forward<ConstBufferSequence>(const_buffer_sequence),
            net::detail::async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)));
    }

    template <typename ConstBuffer, typename CompletionToken>
    decltype(auto) async_write_some(
        ConstBuffer&& buffer, CompletionToken&& completion_token,
        net::detail::sfinae_placeholder<
            std::enable_if_t<net::detail::is_const_buffer<ConstBuffer>::value>>
            _ = net::detail::sfinae) {
        return net::detail::async_operation<net::detail::tags::simple_write>()(
            &get_associated_io_context(), this,
            std::forward<ConstBuffer>(buffer),
            net::detail::async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)));
    }

    template <typename ConstBuffer>
    std::size_t write(
        ConstBuffer&& const_buffer, std::error_code& ec,
        net::detail::sfinae_placeholder<
            std::enable_if_t<net::detail::is_const_buffer<ConstBuffer>::value>>
            _ = net::detail::sfinae) noexcept(true) {
        ec.clear();
        net::const_buffer buf =
            net::buffer(std::forward<ConstBuffer>(const_buffer));
        ssize_t r = 0;
        if (r = ::write(native_handler(), buf.data(), buf.size()); r == -1) {
            net::assign_ec(ec, errno);
        }
        return r;
    }
    template <typename ConstBuffer>
    std::size_t write(
        ConstBuffer&& const_buffer,
        net::detail::sfinae_placeholder<
            std::enable_if_t<net::detail::is_const_buffer<ConstBuffer>::value>>
            _ = net::detail::sfinae) {
        std::error_code ec;
        std::size_t r = write(std::forward<ConstBuffer>(const_buffer), ec);
        if (!ec) {
            return r;
        } else {
            __CHXNET_THROW_EC(ec);
        }
    }

    template <typename MutableBuffer, typename CompletionToken>
    decltype(auto)
    async_read_some(MutableBuffer&& buffer, CompletionToken&& completion_token,
                    net::detail::sfinae_placeholder<std::enable_if_t<
                        net::detail::is_mutable_buffer<MutableBuffer>::value>>
                        _ = net::detail::sfinae) {
        return net::detail::async_operation<net::detail::tags::simple_read>()(
            &get_associated_io_context(), this,
            std::forward<MutableBuffer>(buffer),
            net::detail::async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)));
    }

    template <typename MutableBuffer>
    std::size_t read(MutableBuffer&& mutable_buffer, std::error_code& ec,
                     net::detail::sfinae_placeholder<std::enable_if_t<
                         net::detail::is_mutable_buffer<MutableBuffer>::value>>
                         _ = net::detail::sfinae) noexcept(true) {
        ec.clear();
        net::mutable_buffer buf =
            net::buffer(std::forward<MutableBuffer>(mutable_buffer));
        ssize_t r = 0;
        if (r = ::read(native_handler(), buf.data(), buf.size()); r == -1) {
            net::assign_ec(ec, errno);
        }
        return r;
    }
    template <typename MutableBuffer>
    std::size_t read(MutableBuffer&& mutable_buffer,
                     net::detail::sfinae_placeholder<std::enable_if_t<
                         net::detail::is_mutable_buffer<MutableBuffer>::value>>
                         _ = net::detail::sfinae) {
        std::error_code ec;
        std::size_t r = read(std::forward<MutableBuffer>(mutable_buffer), ec);
        if (!ec) {
            return r;
        } else {
            __CHXNET_THROW_EC(ec);
        }
    }

    template <typename MutableBufferSequence, typename CompletionToken>
    decltype(auto) async_read_some(
        MutableBufferSequence&& mutable_buffer_sequence,
        CompletionToken&& completion_token,
        net::detail::sfinae_placeholder<
            std::enable_if_t<is_mutable_buffer_sequence<
                std::remove_reference_t<MutableBufferSequence>>::value>>
            _ = net::detail::sfinae) {
        return net::detail::async_operation<net::detail::tags::readv>()(
            &get_associated_io_context(), this,
            std::forward<MutableBufferSequence>(mutable_buffer_sequence),
            net::detail::async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)));
    }
};
}  // namespace chx::net

template <typename Sock, typename CompletionToken>
decltype(auto)
chx::net::detail::async_operation<chx::net::detail::tags::sock_poll>::
operator()(io_context* ctx, Sock& sock, int event,
           CompletionToken&& completion_token) {
    io_context::task_t* task = ctx->acquire();
    auto* sqe = ctx->get_sqe(task);
    io_uring_prep_poll_add(sqe, sock.native_handler(), event);

    return detail::async_token_init(
        task->__M_token.emplace(detail::async_token_generate(
            task,
            [](auto& token, io_context::task_t* self) -> int {
                token(get_ec(self), get_res(self));
                return 0;
            },
            completion_token)),
        completion_token);
}

template <typename CompletionToken>
decltype(auto)
chx::net::stream_base::async_poll(int event,
                                  CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::sock_poll>()(
        &get_associated_io_context(), *this, event,
        detail::async_token_bind<const std::error_code&, unsigned short>(
            std::forward<CompletionToken>(completion_token)));
}

template <typename Sock, typename BindCompletionToken>
decltype(auto)
chx::net::detail::async_operation<chx::net::detail::tags::sock_poll>::multi(
    io_context* ctx, Sock& sock, int event,
    BindCompletionToken&& bind_completion_token) {
    io_context::task_t* task = ctx->acquire();
    task->__M_notif = true;

    io_uring_sqe* sqe = ctx->get_sqe(task);
    io_uring_prep_poll_add(sqe, sock.native_handler(), event);
    sqe->len |= IORING_POLL_ADD_MULTI;

    return async_token_init(
        task->__M_token.emplace(async_token_generate(
            task,
            [](auto& token, io_context::task_t* self) -> int {
                token(get_ec(self), self->__M_cqe->flags & IORING_CQE_F_MORE,
                      get_res(self));
                return 0;
            },
            bind_completion_token)),
        bind_completion_token);
}

template <typename CompletionToken>
decltype(auto)
chx::net::stream_base::async_poll_multi(int event,
                                        CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::sock_poll>().multi(
        &get_associated_io_context(), *this, event,
        detail::async_token_bind<const std::error_code&, bool, unsigned short>(
            std::forward<CompletionToken>(completion_token)));
}
