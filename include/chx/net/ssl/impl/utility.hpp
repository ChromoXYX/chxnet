#pragma once

#include "../../io_context.hpp"

namespace chx::net::detail::tags {
struct use_poll {};
struct ssl_use_delivery {};
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
struct chx::net::detail::async_operation<
    chx::net::detail::tags::ssl_use_delivery> {
    template <typename... Signature, typename FinalFunctor,
              typename CompletionToken>
    decltype(auto) oper(io_context* ctx, FinalFunctor&& final_functor,
                        CompletionToken&& completion_token) {
        return ctx->async_delivery<Signature...>(
            std::forward<FinalFunctor>(final_functor),
            std::forward<CompletionToken>(completion_token));
    }
};
