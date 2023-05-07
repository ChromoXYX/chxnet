#pragma once

#include "./ssl_rw_poll.hpp"

#include "../stream.hpp"

template <typename Socket>
template <typename MutableBuffer, typename CompletionToken>
decltype(auto) chx::net::ssl::stream<Socket>::async_read_some(
    MutableBuffer&& buffer, CompletionToken&& completion_token,
    net::detail::sfinae_placeholder<std::enable_if_t<
        net::detail::is_mutable_buffer<MutableBuffer>::value>>) {
    struct ssl_operation {
        constexpr ssl_operation(const mutable_buffer& b) noexcept(true)
            : buf(b) {}

        mutable_buffer buf;

        int operator()(SSL* ssl) noexcept(true) {
            return SSL_read(ssl, buf.data(), buf.size());
        }
    };
    return async_combine<const std::error_code&, std::size_t>(
        Socket::get_associated_io_context(),
        chx::net::ssl::detail::ssl_rw_poll<stream<Socket>, ssl_operation>(
            this, buffer),
        std::forward<CompletionToken>(completion_token));
}
