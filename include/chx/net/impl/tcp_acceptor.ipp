#pragma once

#include "../tcp.hpp"
#include "./general_ip_io.hpp"

#include "../async_token.hpp"

namespace chx::net::ip {
class tcp::acceptor : public socket_base {
  public:
    /**
     * @brief Construct a new acceptor object.
     *
     * @param ctx The associated io_context.
     */
    acceptor(io_context& ctx) : socket_base(&ctx) {}
    /**
     * @brief Construct a new acceptor object, which listens on specific
     * endpoint.
     *
     * @param ctx The associated io_context.
     * @param ep The endpoint to be listened on.
     * @param reuse_port Whether to set SO_REUSEPORT for the acceptor.
     */
    acceptor(io_context& ctx, const endpoint& ep, bool reuse_port = true)
        : socket_base(&ctx) {
        open(ep.protocol());
        if (reuse_port) {
            set_option(SOL_SOCKET, SO_REUSEPORT, true);
        }
        bind(ep);
        listen();
    }
    /**
     * @brief Construct a new and opened acceptor object.
     *
     * @param ctx The associated io_context.
     * @param protocol The protocol selected for the acceptor.
     */
    acceptor(io_context& ctx, const tcp& protocol) : socket_base(&ctx) {
        open(protocol);
    }
    /**
     * @brief Move-construct a new acceptor object.
     *
     * @param other The acceptor to be moved.
     */
    acceptor(acceptor&& other) : socket_base(std::move(other)) {}

    constexpr acceptor& lower_layer() noexcept(true) { return *this; }
    constexpr const acceptor& lower_layer() const noexcept(true) {
        return *this;
    }
    constexpr acceptor& lowest_layer() noexcept(true) { return lower_layer(); }
    constexpr const acceptor& lowest_layer() const noexcept(true) {
        return lower_layer();
    }

    /**
     * @brief Start listening.
     *
     * @param backlog The maximum length to which the queue of pending
     * connections for the acceptor may grow.
     */
    void listen(int backlog = SOMAXCONN) {
        if (::listen(__M_fd, backlog) == -1) {
            __CHXNET_THROW(errno);
        }
    }
    /**
     * @brief Start listening.
     *
     * @param backlog The maximum length to which the queue of pending
     * connections for the acceptor may grow.
     * @param ec The error_code which carries error information.
     */
    void listen(int backlog, std::error_code& ec) noexcept(true) {
        if (::listen(__M_fd, backlog) == -1) {
            net::assign_ec(ec, errno);
        } else {
            ec.clear();
        }
    }

    /**
     * @brief Submit an accept async task.
     *
     * @tparam CompletionToken Callable object with signature
     * \code
     * void(const std::error_code&, ip::tcp::socket)
     * \endcode
     * @param token Completion token which will be invoked when the
     * async task is completed.
     * @return decltype(auto)
     */
    template <typename CompletionToken>
    decltype(auto) async_accept(CompletionToken&& token) {
        return net::detail::async_operation<ip::detail::tags::async_accept>()
            .f<tcp>(&get_associated_io_context(), this,
                    net::detail::async_token_bind<const std::error_code&,
                                                  ip::tcp::socket>(
                        std::forward<CompletionToken>(token)));
    }
};
}  // namespace chx::net::ip
