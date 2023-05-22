#pragma once

#include "./ssl_no_ktls.hpp"

#include "../stream.hpp"

template <typename Socket>
template <typename CompletionToken>
decltype(auto) chx::net::ssl::stream_noktls<Socket>::async_do_handshake(
    CompletionToken&& completion_token) {
    struct ssl_operation {
        int operator()(SSL* ssl) const noexcept(true) {
            return SSL_do_handshake(ssl);
        }
    };
    return async_combine<const std::error_code&>(
        Socket::get_associated_io_context(),
        std::forward<CompletionToken>(completion_token),
        net::detail::type_identity<chx::net::ssl::detail::ssl_no_ktls<
            stream_noktls<Socket>, ssl_operation>>(),
        this);
}
