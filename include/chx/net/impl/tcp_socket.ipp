#pragma once

#include <linux/limits.h>

#include "../tcp.hpp"
#include "./basic_ip_socket.hpp"
#include "./general_ip_io.hpp"

#ifndef CHXNET_SPLICE_SIZE
#define CHXNET_SPLICE_SIZE 65536
#endif

namespace chx::net::ip {
class tcp::socket : public detail::basic_socket<tcp> {
  public:
    /**
     * @brief Construct a new socket object.
     *
     * @param ctx The associated io_context.
     */
    socket(io_context& ctx) : detail::basic_socket<tcp>(ctx) {}
    /**
     * @brief Construct a new and opened socket object.
     *
     * @param ctx The associated io_context.
     * @param protocol The protocol selected for the socket.
     */
    socket(io_context& ctx, const tcp& protocol)
        : detail::basic_socket<tcp>(ctx) {
        open(protocol);
    }
    /**
     * @brief Construct a new socket object, which bound to specific endpoint.
     *
     * @param ctx The associated io_context.
     * @param ep The endpoint assigned to the socket.
     */
    socket(io_context& ctx, const endpoint& ep)
        : detail::basic_socket<tcp>(ctx) {
        open(ep.protocol());
        bind(ep);
    }
    /**
     * @brief Construct a new socket object from a native handler.
     *
     * @param ctx The associated io_context.
     * @param fd The native handler assigned to the socket.
     */
    socket(io_context& ctx, int fd) : detail::basic_socket<tcp>(ctx) {
        __M_fd = fd;
    }
    /**
     * @brief Move-construct a new socket object.
     *
     * @param other The socket to be moved.
     */
    socket(socket&& other) noexcept(true)
        : detail::basic_socket<tcp>(std::move(other)) {}

    socket(io_context& ctx, socket&& other) noexcept(true)
        : detail::basic_socket<tcp>(ctx, std::move(other)) {}

    socket& operator=(socket&& other) noexcept(true) {
        if (this == &other) {
            return *this;
        }
        stream_base::operator=(std::move(other));
        return *this;
    }

    constexpr socket& lower_layer() noexcept(true) { return *this; }
    constexpr const socket& lower_layer() const noexcept(true) { return *this; }
    constexpr socket& lowest_layer() noexcept(true) { return lower_layer(); }
    constexpr const socket& lowest_layer() const noexcept(true) {
        return lower_layer();
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
    decltype(auto) async_connect(const ip::tcp::endpoint& end_point,
                                 CompletionToken&& completion_token) {
        return net::detail::async_operation<detail::tags::connect2>()(
            &get_associated_io_context(),
            net::detail::async_operation<detail::tags::connect2>::c2(
                end_point,
                net::detail::async_token_bind<const std::error_code&>(
                    std::forward<CompletionToken>(completion_token)),
                native_handler()));
    }

    void connect(const ip::tcp::endpoint& endpoint,
                 std::error_code& ec) noexcept(true) {
        ec.clear();
        union {
            struct sockaddr_in in;
            struct sockaddr_in6 in6;
        } st = {};
        if (endpoint.address().is_v4()) {
            st.in = endpoint.sockaddr_in();
        } else {
            st.in6 = endpoint.sockaddr_in6();
        }
        if (::connect(native_handler(), (const struct sockaddr*)&st,
                      endpoint.address().is_v4()
                          ? sizeof(sockaddr_in)
                          : sizeof(sockaddr_in6)) == -1) {
            net::assign_ec(ec, errno);
        }
    }
    void connect(const ip::tcp::endpoint& endpoint) {
        std::error_code ec;
        connect(endpoint, ec);
        if (ec) {
            __CHXNET_THROW_EC(ec);
        }
    }

    template <typename ConstBuffer, typename CompletionToken>
    decltype(auto) async_write_some_zero_copy(
        ConstBuffer&& const_buffer, CompletionToken&& completion_token,
        net::detail::sfinae_placeholder<
            std::enable_if_t<net::detail::is_const_buffer<ConstBuffer>::value>>
            _ = net::detail::sfinae) {
        return net::detail::async_operation<net::detail::tags::simple_write>()
            .zero_copy(&get_associated_io_context(), this,
                       std::forward<ConstBuffer>(const_buffer),
                       net::detail::async_token_bind<const std::error_code&,
                                                     std::size_t>(
                           std::forward<CompletionToken>(completion_token)));
    }
};
}  // namespace chx::net::ip
