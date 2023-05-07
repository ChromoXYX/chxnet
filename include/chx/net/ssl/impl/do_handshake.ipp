#pragma once

#include "./ssl_poll.hpp"

#include "../stream.hpp"

template <typename Socket>
template <typename CompletionToken>
decltype(auto) chx::net::ssl::stream<Socket>::async_do_handshake(
    CompletionToken&& completion_token) {
    struct ssl_operation {
        int operator()(SSL* ssl) const noexcept(true) {
            return SSL_do_handshake(ssl);
        }
    };
    return async_combine<const std::error_code&>(
        Socket::get_associated_io_context(),
        chx::net::ssl::detail::ssl_poll<stream<Socket>, ssl_operation>(this),
        std::forward<CompletionToken>(completion_token));
}
