#pragma once

#include "../error_code.hpp"
#include "./utility.hpp"

#include <openssl/ssl.h>
#include <poll.h>

namespace chx::net::ssl::detail {
template <typename Stream, typename SSLOperation, typename CntlType = void>
struct ssl_rw_poll : SSLOperation {
    template <typename... Args>
    ssl_rw_poll(Stream* s, Args&&... args) noexcept(
        std::is_nothrow_constructible_v<SSLOperation, Args&&...>)
        : sock(s), SSLOperation(std::forward<Args>(args)...) {}

    using use_poll = net::detail::async_operation<net::detail::tags::use_poll>;
    Stream* const sock;

    template <typename T> using rebind = ssl_rw_poll<Stream, SSLOperation, T>;

    template <typename Cntl> void perform(Cntl& cntl) {
        ERR_clear_error();
        int r = SSLOperation::operator()(sock->get_associated_SSL());
        if (r > 0) {
            return cntl.complete(std::error_code{}, r);
        } else {
            int code = SSL_get_error(sock->get_associated_SSL(), r);
            if (code == SSL_ERROR_WANT_READ) {
                return use_poll()(*sock, POLLIN, cntl.next());
            } else if (code == SSL_ERROR_WANT_WRITE) {
                return use_poll()(*sock, POLLOUT, cntl.next());
            } else if (code == SSL_ERROR_SYSCALL) {
                return cntl.complete(net::detail::make_ec(errno), 0);
            } else if (code == SSL_ERROR_ZERO_RETURN) {
                return cntl.complete(net::detail::make_ec(errc::eof), 0);
            } else {
                return cntl.complete(make_ssl_ec(code), 0);
            }
        }
    }

    template <typename Cntl> void operator()(Cntl& cntl) {
        static_assert(!std::is_same_v<CntlType, void>);
        // if (!  // sock->get_associated_io_context().__M_destructing
        //     net::detail::async_operation<
        //         net::detail::tags::ssl_check_destructing>()(
        //         &sock->get_associated_io_context())) {
        perform(cntl);
        // } else {
        //     cntl.complete(net::detail::make_ec(net::errc::operation_canceled),
        //                   0);
        // }
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& ec, int revents) {
        if (!ec) {
            if (revents == POLLIN || revents == POLLOUT) {
                return perform(cntl);
            } else {
                if (revents & (POLLRDHUP | POLLHUP)) {
                    return cntl.complete(net::detail::make_ec(errc::eof), 0);
                } else {
                    return cntl.complete(
                        net::detail::make_ec(errc::internal_error), 0);
                }
            }
        } else {
            return cntl.complete(ec, 0);
        }
    }
};
}  // namespace chx::net::ssl::detail
