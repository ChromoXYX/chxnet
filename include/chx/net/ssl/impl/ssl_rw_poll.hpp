#pragma once

#include "../error_code.hpp"
#include "./utility.hpp"

#include <openssl/ssl.h>
#include <poll.h>

namespace chx::net::ssl::detail {
template <typename Stream, typename SSLOperation>
struct ssl_rw_poll : SSLOperation {
    struct res_tag {};

    template <typename... Args>
    ssl_rw_poll(Stream* s, Args&&... args) noexcept(
        std::is_nothrow_constructible_v<SSLOperation, Args&&...>)
        : sock(s), SSLOperation(std::forward<Args>(args)...) {}

    using use_poll = net::detail::async_operation<net::detail::tags::use_poll>;
    using use_delivery =
        net::detail::async_operation<net::detail::tags::use_delivery>;
    Stream* const sock;

    template <typename Cntl> void perform(Cntl& cntl) {
        ERR_clear_error();
        int r = SSLOperation::operator()(sock->get_associated_SSL());
        if (r > 0) {
            return use_delivery()
                .oper<const std::error_code&, std::size_t, res_tag>(
                    &sock->get_associated_io_context(),
                    [sz = r](auto& token,
                             io_context::task_t* self) mutable -> int {
                        token(self->__M_ec, sz, res_tag{});
                        return 0;
                    },
                    cntl.next());
        } else {
            int code = SSL_get_error(sock->get_associated_SSL(), r);
            int current_errno = errno;
            if (code == SSL_ERROR_WANT_READ) {
                return use_poll()(*sock, POLLIN, cntl.next());
            } else if (code == SSL_ERROR_WANT_WRITE) {
                return use_poll()(*sock, POLLOUT, cntl.next());
            } else if (code == SSL_ERROR_SYSCALL) {
                return use_delivery()
                    .oper<const std::error_code&, std::size_t, res_tag>(
                        &sock->get_associated_io_context(),
                        [current_errno](
                            auto& token,
                            io_context::task_t* self) mutable -> int {
                            token(net::detail::make_ec(current_errno), 0,
                                  res_tag{});
                            return 0;
                        },
                        cntl.next());
            } else if (code == SSL_ERROR_ZERO_RETURN) {
                return use_delivery()
                    .oper<const std::error_code&, std::size_t, res_tag>(
                        &sock->get_associated_io_context(),
                        [](auto& token,
                           io_context::task_t* self) mutable -> int {
                            token(net::detail::make_ec(net::errc::eof), 0,
                                  res_tag{});
                            return 0;
                        },
                        cntl.next());
            } else {
                return use_delivery()
                    .oper<const std::error_code&, std::size_t, res_tag>(
                        &sock->get_associated_io_context(),
                        [code](auto& token,
                               io_context::task_t* self) mutable -> int {
                            token(make_ssl_ec(code), 0, res_tag{});
                            return 0;
                        },
                        cntl.next());
            }
        }
    }

    template <typename Cntl> void operator()(Cntl& cntl) { perform(cntl); }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& ec, int revents) {
        if (!ec) {
            if (revents == POLLIN || revents == POLLOUT) {
                return perform(cntl);
            } else {
                if (revents & (POLLRDHUP | POLLHUP)) {
                    return use_delivery()
                        .oper<const std::error_code&, std::size_t, res_tag>(
                            &sock->get_associated_io_context(),
                            [](auto& token,
                               io_context::task_t* self) mutable -> int {
                                token(net::detail::make_ec(net::errc::eof), 0,
                                      res_tag{});
                                return 0;
                            },
                            cntl.next());
                } else {
                    return use_delivery()
                        .oper<const std::error_code&, std::size_t, res_tag>(
                            &sock->get_associated_io_context(),
                            [](auto& token,
                               io_context::task_t* self) mutable -> int {
                                token(net::detail::make_ec(
                                          net::errc::internal_error),
                                      0, res_tag{});
                                return 0;
                            },
                            cntl.next());
                }
            }
        } else {
            return use_delivery()
                .oper<const std::error_code&, std::size_t, res_tag>(
                    &sock->get_associated_io_context(),
                    [ec](auto& token, io_context::task_t* self) mutable -> int {
                        token(ec, 0, res_tag{});
                        return 0;
                    },
                    cntl.next());
        }
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& ec, std::size_t sz,
                    res_tag) {
        cntl.complete(ec, sz);
    }
};
}  // namespace chx::net::ssl::detail
