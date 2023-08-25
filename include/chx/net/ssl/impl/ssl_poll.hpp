#pragma once

#include "../error_code.hpp"
#include "./utility.hpp"

#include <openssl/ssl.h>
#include <poll.h>

namespace chx::net::ssl::detail {
template <typename Stream, typename SSLOperation, typename CntlType = void>
struct ssl_poll : SSLOperation {
    template <typename... Args>
    ssl_poll(Stream* s, Args&&... args) noexcept(
        std::is_nothrow_constructible_v<SSLOperation, Args&&...>)
        : sock(s), SSLOperation(std::forward<Args>(args)...) {}

    using use_poll = net::detail::async_operation<net::detail::tags::use_poll>;
    Stream* const sock;

    template <typename T> using rebind = ssl_poll<Stream, SSLOperation, T>;

    template <typename Cntl> void perform(Cntl& cntl) {
        ERR_clear_error();
        int r = SSLOperation::operator()(sock->get_associated_SSL());
        if (r == 1) {
            sock->get_associated_io_context().async_nop(cntl.next());
        } else {
            int code = SSL_get_error(sock->get_associated_SSL(), r);
            if (code == SSL_ERROR_WANT_READ) {
                return use_poll()(*sock, POLLIN, cntl.next());
            } else if (code == SSL_ERROR_WANT_WRITE) {
                return use_poll()(*sock, POLLOUT, cntl.next());
            } else if (code == SSL_ERROR_SYSCALL) {
                return cntl.complete(net::detail::make_ec(errno));
            } else {
                return cntl.complete(make_ssl_ec(code));
            }
        }
    }

    template <typename Cntl> void operator()(Cntl& cntl) {
        static_assert(!std::is_same_v<CntlType, void>);
        if (!  // sock->get_associated_io_context().__M_destructing
            net::detail::async_operation<
                net::detail::tags::ssl_check_destructing>()(
                &sock->get_associated_io_context())) {
            perform(cntl);
        } else {
            cntl.complete(net::detail::make_ec(net::errc::operation_canceled));
        }
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& ec, int revents) {
        if (!ec) {
            if (revents == POLLIN || revents == POLLOUT) {
                return perform(cntl);
            } else {
                if (revents & (POLLRDHUP | POLLHUP)) {
                    return cntl.complete(net::detail::make_ec(errc::eof));
                } else {
                    return cntl.complete(
                        net::detail::make_ec(errc::internal_error));
                }
            }
        } else {
            return cntl.complete(ec);
        }
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& ec) {
        cntl.complete(ec);
    }
};
}  // namespace chx::net::ssl::detail
