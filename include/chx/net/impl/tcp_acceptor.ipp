#pragma once

#include "../tcp.hpp"
#include "./tcp_socket.ipp"

#include "../async_token.hpp"

namespace chx::net::ip::detail::tags {
struct async_accept {};
}  // namespace chx::net::ip::detail::tags

template <>
struct chx::net::detail::async_operation<
    chx::net::ip::detail::tags::async_accept> {
    template <typename CompletionToken>
    decltype(auto) operator()(io_context* ctx, ip::tcp::acceptor* acceptor,
                              CompletionToken&& completion_token);
};

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
     * @param reuse_addr Whether to set SO_REUSEADDR for the acceptor.
     */
    acceptor(io_context& ctx, const endpoint& ep, bool reuse_addr = true)
        : socket_base(&ctx) {
        open(ep.protocol());
        if (reuse_addr) {
            set_option(SOL_SOCKET, SO_REUSEADDR, true);
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
            net::detail::assign_ec(ec, errno);
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
        return net::detail::async_operation<detail::tags::async_accept>()(
            &get_associated_io_context(), this,
            net::detail::async_token_bind<const std::error_code&,
                                          ip::tcp::socket>(
                std::forward<CompletionToken>(token)));
    }
};
}  // namespace chx::net::ip

inline static int accept_count = 0;

template <typename CompletionToken>
auto chx::net::detail::
    async_operation<chx::net::ip::detail::tags::async_accept>::operator()(
        io_context* ctx, ip::tcp::acceptor* acceptor,
        CompletionToken&& completion_token) -> decltype(auto) {
    io_context::task_t* task =
        !ctx->is_closed() ? ctx->acquire() : ctx->acquire_after_close();
    if (!ctx->is_closed()) {
        auto* sqe = ctx->get_sqe();
        io_uring_sqe_set_data(sqe, task);
        io_uring_prep_accept(sqe, acceptor->native_handler(), nullptr, nullptr,
                             0);
    }
    task->__M_additional = reinterpret_cast<std::uint64_t>(acceptor);
    return detail::async_token_init(
        task->__M_token.emplace(detail::async_token_generate(
            task,
            [](auto& completion_token,
               io_context::task_t* self) mutable -> int {
                auto* acceptor =
                    reinterpret_cast<ip::tcp::acceptor*>(self->__M_additional);
                completion_token(
                    self->__M_ec,
                    ip::tcp::socket(acceptor->get_associated_io_context(),
                                    self->__M_res > 0 ? self->__M_res : -1));
                return 0;
            },
            std::forward<CompletionToken>(completion_token))),
        std::forward<CompletionToken>(completion_token));
}
