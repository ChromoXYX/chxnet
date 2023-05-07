#pragma once

#include "../error_code.hpp"
#include "./utility.hpp"

#include <openssl/ssl.h>
#include <poll.h>

namespace chx::net::ssl::detail {
template <typename Stream, typename SSLOperation>
struct ssl_poll : SSLOperation {
    template <typename... Args>
    ssl_poll(Stream* s, Args&&... args) noexcept(
        std::is_nothrow_constructible_v<SSLOperation, Args&&...>)
        : sock(s), SSLOperation(std::forward<Args>(args)...) {}

    using use_poll = net::detail::async_operation<net::detail::tags::use_poll>;
    using use_delivery =
        net::detail::async_operation<net::detail::tags::ssl_use_delivery>;
    Stream* const sock;
    enum poll_t : int { nop = 0, poll_in = POLLIN, poll_out = POLLOUT };
    poll_t poll_type = nop;

    template <typename Cntl> void perform(Cntl& cntl) {
        ERR_clear_error();
        int r = SSLOperation::operator()(sock->get_associated_SSL());
        if (r == 1) {
            sock->get_associated_io_context().async_nop(cntl.next());
        } else {
            int code = SSL_get_error(sock->get_associated_SSL(), r);
            if (code == SSL_ERROR_WANT_READ) {
                poll_type = poll_in;
                return use_poll()(*sock, POLLIN, cntl.next());
            } else if (code == SSL_ERROR_WANT_WRITE) {
                poll_type = poll_out;
                return use_poll()(*sock, POLLOUT, cntl.next());
            } else if (code == SSL_ERROR_SYSCALL) {
                int ec = errno;
                return use_delivery().oper<const std::error_code&>(
                    &sock->get_associated_io_context(),
                    [ec](auto& token, io_context::task_t* self) mutable -> int {
                        token(net::detail::make_ec(ec));
                        return 0;
                    },
                    cntl.next());
            } else {
                return use_delivery().oper<const std::error_code&>(
                    &sock->get_associated_io_context(),
                    [code](auto& token,
                           io_context::task_t* self) mutable -> int {
                        token(make_ssl_ec(code));
                        return 0;
                    },
                    cntl.next());
            }
        }
    }

    template <typename Cntl> void operator()(Cntl& cntl) { perform(cntl); }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& ec, int revents) {
        if (poll_type && (poll_type == revents)) {
            return perform(cntl);
        } else {
            if (revents & (POLLRDHUP | POLLHUP)) {
                return use_delivery().oper<const std::error_code&>(
                    &sock->get_associated_io_context(),
                    [](auto& token, io_context::task_t* self) mutable -> int {
                        token(net::detail::make_ec(net::errc::eof));
                        return 0;
                    },
                    cntl.next());
            } else {
                return use_delivery().oper<const std::error_code&>(
                    &sock->get_associated_io_context(),
                    [](auto& token, io_context::task_t* self) mutable -> int {
                        token(net::detail::make_ec(net::errc::internal_error));
                        return 0;
                    },
                    cntl.next());
            }
        }
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& ec) {
        cntl.complete(ec);
    }
};
}  // namespace chx::net::ssl::detail