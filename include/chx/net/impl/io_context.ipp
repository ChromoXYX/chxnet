#pragma once

#include "../io_context.hpp"
#include "../async_token.hpp"

namespace chx::net::detail {
namespace tags {
struct delivery {};
template <typename RetType> struct async_post {};
}  // namespace tags
template <> struct async_operation<tags::delivery> {
    template <typename FinalFunctor, typename CompletionToken>
    decltype(auto) operator()(io_context* ctx, FinalFunctor&& final_functor,
                              CompletionToken&& token);
};
}  // namespace chx::net::detail

template <typename FinalFunctor, typename CompletionToken>
decltype(auto)
chx::net::detail::async_operation<chx::net::detail::tags::delivery>::operator()(
    io_context* ctx, FinalFunctor&& final_functor, CompletionToken&& token) {
    io_context::task_t* task = ctx->acquire();
    auto* sqe = ctx->get_sqe(task);
    io_uring_prep_nop(sqe);

    return detail::async_token_init(
        task->__M_token.emplace(detail::async_token_generate(
            task, std::forward<FinalFunctor>(final_functor),
            std::forward<CompletionToken>(token))),
        std::forward<CompletionToken>(token));
}

template <typename... Signature, typename FinalFunctor,
          typename CompletionToken>
decltype(auto)
chx::net::io_context::async_delivery(FinalFunctor&& final_functor,
                                     CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::delivery>()(
        this, std::forward<FinalFunctor>(final_functor),
        detail::async_token_bind<Signature...>(
            std::forward<CompletionToken>(completion_token)));
}

template <typename CompletionToken>
decltype(auto)
chx::net::io_context::async_nop(CompletionToken&& completion_token) {
    return async_delivery<const std::error_code&>(
        [](auto& token, task_t* self) mutable -> int {
            token(self->__M_ec);
            return 0;
        },
        std::forward<CompletionToken>(completion_token));
}
