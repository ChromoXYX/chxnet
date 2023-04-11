#pragma once

#include "../io_context.hpp"
#include "../tcp.hpp"

namespace chx::net::ip::detail::tags {
struct cancel_fd {};
}  // namespace chx::net::ip::detail::tags

template <>
struct chx::net::detail::async_operation<
    ::chx::net::ip::detail::tags::cancel_fd> {
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

class chx::net::ip::tcp::socket_base {
  protected:
    const io_context* __M_ctx = nullptr;
    int __M_fd = -1;
    std::size_t __M_associated_task = 0;

    constexpr socket_base(io_context* ctx) noexcept(true) : __M_ctx(ctx) {
        assert(ctx != nullptr);
    }
    socket_base(socket_base&& other) noexcept(true)
        : __M_ctx(other.__M_ctx),
          __M_fd(std::exchange(other.__M_fd, -1)),
          __M_associated_task(std::exchange(other.__M_associated_task, 0)) {}

  public:
    /**
     * @brief Ways to shutdown the connection.
     *
     */
    enum shutdown_type : int {
        shutdown_receive = SHUT_RD,
        shutdown_write = SHUT_WR,
        shutdown_both = SHUT_RDWR
    };

    ~socket_base() {
        if (is_open()) {
            std::error_code ec;
            cancel();
            close(ec);
        }
    }

    /**
     * @brief Get the native handler.
     *
     * @return constexpr int
     */
    constexpr int native_handler() const noexcept(true) { return __M_fd; }
    /**
     * @brief Get the associated io_context object.
     *
     * @return constexpr io_context&
     */
    constexpr io_context& get_associated_io_context() const noexcept(true) {
        return const_cast<io_context&>(*__M_ctx);
    }

    /**
     * @brief Check whether the socket is open.
     *
     * @return true The socket is open.
     * @return false The socket is closed.
     */
    bool is_open() const noexcept(true) {
        return native_handler() != -1 &&
               (::fcntl(native_handler(), F_GETFD) || errno != EBADF);
    }

    /**
     * @brief Set the boolean options for the socket.
     *
     * @param level The level at which the option resides.
     * @param name Name for the option.
     * @param value The boolean value for the option.
     * @param ec The error_code which carries error information.
     */
    void set_option(int level, int name, bool value,
                    std::error_code& ec) noexcept(true) {
        int v = value ? 1 : 0;
        if (::setsockopt(__M_fd, level, name, &v, sizeof(v)) == 0) {
            ec.clear();
        } else {
            net::detail::assign_ec(ec, errno);
        }
    }
    /**
     * @brief Set the int options for the socket.
     *
     * @param level The level at which the option resides.
     * @param name Name for the option.
     * @param value The int value for the option.
     * @param ec The error_code which carries error information.
     */
    void set_option(int level, int name, int value,
                    std::error_code& ec) noexcept(true) {
        if (::setsockopt(__M_fd, level, name, &value, sizeof(value)) == 0) {
            ec.clear();
        } else {
            net::detail::assign_ec(ec, errno);
        }
    }
    /**
     * @brief Set the boolean options for the socket.
     *
     * @param level The level at which the option resides.
     * @param name Name for the option.
     * @param value The boolean value for the option.
     */
    void set_option(int level, int name, bool value) {
        std::error_code ec;
        set_option(level, name, value, ec);
        if (ec) {
            __CHXNET_THROW_EC(ec);
        }
    }
    /**
     * @brief Set the int options for the socket.
     *
     * @param level The level at which the option resides.
     * @param name Name for the option.
     * @param value The int value for the option.
     */
    void set_option(int level, int name, int value) {
        std::error_code ec;
        set_option(level, name, value, ec);
        if (ec) {
            __CHXNET_THROW_EC(ec);
        }
    }

    /**
     * @brief Shutdown the socket.
     *
     * @param how How to shutdown the connection.
     */
    void shutdown(shutdown_type how) {
        if (::shutdown(__M_fd, how) == 0) {
            return;
        } else {
            __CHXNET_THROW(errno);
        }
    }
    /**
     * @brief Shutdown the socket.
     *
     * @param how How to shutdown the connection.
     * @param ec The error_code which carries error information.
     */
    void shutdown(shutdown_type how, std::error_code& ec) noexcept(true) {
        if (is_open()) {
            if (::shutdown(__M_fd, how) == 0) {
                ec.clear();
            } else {
                net::detail::assign_ec(ec, errno);
            }
        }
    }

    /**
     * @brief Close the socket.
     *
     */
    void close() {
        std::error_code ec;
        close(ec);
        if (ec) {
            __CHXNET_THROW_EC(ec);
        }
    }
    /**
     * @brief Close the socket.
     *
     * @param ec The error_code which carries error information.
     */
    void close(std::error_code& ec) noexcept(true) {
        if (::close(__M_fd) == -1) {
            net::detail::assign_ec(ec, errno);
        } else {
            ec.clear();
        }
        __M_fd = -1;
    }

    /**
     * @brief Cancel all associated async tasks on the socket.
     *
     */
    void cancel() {
        net::detail::async_operation<detail::tags::cancel_fd>()(
            &get_associated_io_context(), native_handler());
    }

    /**
     * @brief Open the socket on specific protocol.
     *
     * @details If the socket is valid, close() will be called to close current
     * connection.
     *
     * @param protocol The protocol selected for the socket.
     */
    void open(const tcp& protocol = tcp::v4()) {
        if (is_open()) {
            close();
        }
        if (int new_fd = ::socket(protocol.family(), SOCK_STREAM, 0);
            new_fd > 0) {
            __M_fd = new_fd;
        } else {
            __CHXNET_THROW(errno);
        }
    }
    /**
     * @brief Open the socket on specific protocol.
     *
     * @details If the socket is valid, close() will be called to close current
     * connection.
     *
     * @param protocol The protocol selected for the socket.
     * @param ec The error_code which carries error information.
     */
    void open(const tcp& protocol, std::error_code& ec) noexcept(true) {
        if (is_open()) {
            close(ec);
            if (ec) {
                return;
            }
        }
        if (int new_fd = ::socket(protocol.family(), SOCK_STREAM, 0);
            new_fd > 0) {
            __M_fd = new_fd;
            ec.clear();
        } else {
            net::detail::assign_ec(ec, errno);
        }
    }

    /**
     * @brief Bind the socket on specific endpoint.
     *
     * @param ep Endpoint assigned to the socket.
     */
    void bind(const endpoint& ep) {
        address addr = ep.address();
        if (addr.is_v4()) {
            struct sockaddr_in sar = {};
            sar.sin_family = AF_INET;
            sar.sin_port = htons(ep.port());
            addr.to_v4().assign(&sar.sin_addr.s_addr);
            if (::bind(__M_fd, reinterpret_cast<sockaddr*>(&sar),
                       sizeof(sar)) == -1) {
                __CHXNET_THROW(errno);
            }
        } else {
            struct sockaddr_in6 sar = {};
            sar.sin6_family = AF_INET6;
            sar.sin6_flowinfo = 0;
            sar.sin6_port = htons(ep.port());
            addr.to_v6().assign(&sar.sin6_addr);
            if (::bind(__M_fd, reinterpret_cast<sockaddr*>(&sar),
                       sizeof(sar)) == -1) {
                __CHXNET_THROW(errno);
            }
        }
    }
    /**
     * @brief Bind the socket on specific endpoint.
     *
     * @param ep Endpoint assigned to the socket.
     * @param ec The error_code which carries error information.
     */
    void bind(const endpoint& ep, std::error_code& ec) noexcept(true) {
        address addr = ep.address();
        if (addr.is_v4()) {
            struct sockaddr_in sar = {};
            sar.sin_family = AF_INET;
            sar.sin_port = htons(ep.port());
            addr.to_v4().assign(&sar.sin_addr.s_addr);
            if (::bind(__M_fd, reinterpret_cast<sockaddr*>(&sar),
                       sizeof(sar)) == -1) {
                net::detail::assign_ec(ec, errno);
                return;
            }
        } else {
            struct sockaddr_in6 sar = {};
            sar.sin6_family = AF_INET6;
            sar.sin6_flowinfo = 0;
            sar.sin6_port = htons(ep.port());
            addr.to_v6().assign(&sar.sin6_addr);
            if (::bind(__M_fd, reinterpret_cast<sockaddr*>(&sar),
                       sizeof(sar)) == -1) {
                net::detail::assign_ec(ec, errno);
                return;
            }
        }
    }
};
