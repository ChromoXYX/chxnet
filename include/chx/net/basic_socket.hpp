#pragma once

#include <netinet/in.h>

#include "./io_context.hpp"

namespace chx::net::detail::tags {
struct cancel_fd {};
}  // namespace chx::net::detail::tags

template <>
struct chx::net::detail::async_operation<::chx::net::detail::tags::cancel_fd> {
    void operator()(io_context* ctx, int fd) const {
        if (!ctx->is_closed()) {
            auto* sqe = ctx->get_sqe();
            io_uring_prep_cancel_fd(sqe, fd, IORING_ASYNC_CANCEL_ALL);
            io_uring_sqe_set_data(sqe, nullptr);
            sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
            ctx->submit();
        }
    }
};

namespace chx::net {
template <typename Protocol> class basic_socket {
  protected:
    const io_context* __M_ctx = nullptr;
    int __M_fd = -1;
    std::size_t __M_associated_task = 0;

    constexpr basic_socket(io_context* ctx) noexcept(true) : __M_ctx(ctx) {
        assert(ctx != nullptr);
    }
    basic_socket(basic_socket&& other) noexcept(true)
        : __M_ctx(other.__M_ctx), __M_fd(std::exchange(other.__M_fd, -1)),
          __M_associated_task(std::exchange(other.__M_associated_task, 0)) {}

  public:
    ~basic_socket() {
        if (is_open()) {
            std::error_code ec;
            cancel();
            close(ec);
        }
    }

    constexpr int native_handler() const noexcept(true) { return __M_fd; }

    constexpr io_context& get_associated_io_context() const noexcept(true) {
        return const_cast<io_context&>(*__M_ctx);
    }

    bool is_open() const noexcept(true) {
        return native_handler() != -1 &&
               (::fcntl(native_handler(), F_GETFD) || errno != EBADF);
    }

    void set_option(int level, int name, bool value,
                    std::error_code& ec) noexcept(true) {
        int v = value ? 1 : 0;
        if (::setsockopt(__M_fd, level, name, &v, sizeof(v)) == 0) {
            ec.clear();
        } else {
            net::detail::assign_ec(ec, errno);
        }
    }

    void set_option(int level, int name, int value,
                    std::error_code& ec) noexcept(true) {
        if (::setsockopt(__M_fd, level, name, &value, sizeof(value)) == 0) {
            ec.clear();
        } else {
            net::detail::assign_ec(ec, errno);
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

    void close() {
        std::error_code ec;
        close(ec);
        if (ec) {
            __CHXNET_THROW_EC(ec);
        }
    }

    void close(std::error_code& ec) noexcept(true) {
        if (::close(__M_fd) == -1) {
            net::detail::assign_ec(ec, errno);
        } else {
            ec.clear();
        }
        __M_fd = -1;
    }

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
                net::detail::assign_ec(ec, errno);
            }
        }
    }

    void open(const Protocol& protocol = Protocol::v4()) {
        if (is_open()) {
            close();
        }
        if (int new_fd = ::socket(protocol.family(), protocol.socket_type(), 0);
            new_fd > 0) {
            __M_fd = new_fd;
        } else {
            __CHXNET_THROW(errno);
        }
    }

    void open(const Protocol& protocol, std::error_code& ec) noexcept(true) {
        if (is_open()) {
            close(ec);
            if (ec) {
                return;
            }
        }
        if (int new_fd = ::socket(protocol.family(), protocol.socket_type(), 0);
            new_fd > 0) {
            __M_fd = new_fd;
            ec.clear();
        } else {
            net::detail::assign_ec(ec, errno);
        }
    }

    void bind(const typename Protocol::endpoint& ep) {
        if (ep.address().is_v4()) {
            struct sockaddr_in sar = ep.sockaddr_in();
            if (::bind(__M_fd, reinterpret_cast<sockaddr*>(&sar),
                       sizeof(sar)) == -1) {
                __CHXNET_THROW(errno);
            }
        } else {
            struct sockaddr_in6 sar = ep.sockaddr_in6();
            if (::bind(__M_fd, reinterpret_cast<sockaddr*>(&sar),
                       sizeof(sar)) == -1) {
                __CHXNET_THROW(errno);
            }
        }
    }

    void bind(const typename Protocol::endpoint& ep,
              std::error_code& ec) noexcept(true) {
        if (ep.address().is_v4()) {
            struct sockaddr_in sar = ep.sockaddr_in();
            if (::bind(__M_fd, reinterpret_cast<sockaddr*>(&sar),
                       sizeof(sar)) == -1) {
                net::detail::assign_ec(ec, errno);
                return;
            }
        } else {
            struct sockaddr_in6 sar = ep.sockaddr_in6();
            if (::bind(__M_fd, reinterpret_cast<sockaddr*>(&sar),
                       sizeof(sar)) == -1) {
                net::detail::assign_ec(ec, errno);
                return;
            }
        }
    }
};
}  // namespace chx::net
