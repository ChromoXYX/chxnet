#pragma once

#include "./ssl_poll.hpp"

#include "../stream.hpp"

template <typename Socket>
template <typename CompletionToken>
decltype(auto) chx::net::ssl::stream<Socket>::async_shutdown(
    CompletionToken&& completion_token) {
    struct ssl_operation {
        int operator()(SSL* ssl) const noexcept(true) {
            int r = SSL_shutdown(ssl);
            // just shutdown again if return 0
            return r != 0 ? r : SSL_shutdown(ssl);
        }
    };
    return async_combine<const std::error_code&>(
        Socket::get_associated_io_context(),
        std::forward<CompletionToken>(completion_token),
        net::detail::type_identity<
            chx::net::ssl::detail::ssl_poll<stream<Socket>, ssl_operation>>(),
        this);
}
