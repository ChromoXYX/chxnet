#pragma once

#include "../../io_context.hpp"

namespace chx::net::detail::tags {
struct use_poll {};
struct ssl_submit {};
// struct ssl_check_destructing {};
}  // namespace chx::net::detail::tags

template <>
struct chx::net::detail::async_operation<chx::net::detail::tags::use_poll> {
    template <typename Sock, typename CompletionToken>
    decltype(auto) operator()(Sock& sock, int events,
                              CompletionToken&& completion_token) {
        return sock.async_poll(events,
                               std::forward<CompletionToken>(completion_token));
    }
};

template <>
struct chx::net::detail::async_operation<chx::net::detail::tags::ssl_submit> {
    void operator()(io_context* ctx) { ctx->submit(); }
};

// template <>
// struct chx::net::detail::async_operation<
//     chx::net::detail::tags::ssl_check_destructing> {
//     bool operator()(io_context* ctx) noexcept(true) {
//         return ctx->__M_destruct;
//     }
// };
