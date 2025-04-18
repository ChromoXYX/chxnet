#pragma once

#include "../../io_context.hpp"

namespace chx::net::detail::tags {
struct use_poll {};
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
