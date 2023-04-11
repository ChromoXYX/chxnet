#pragma once

#include "../io_context.hpp"
#include "../async_token.hpp"

template <typename CompletionToken>
decltype(auto)
chx::net::detail::async_operation<chx::net::detail::tags::nop>::operator()(
    io_context* ctx, CompletionToken&& token) {
    io_context::__task_t* task =
        !ctx->is_closed() ? ctx->acquire() : ctx->acquire_after_close();
    if (!ctx->is_closed()) {
        auto* sqe = ctx->get_sqe(task);
        io_uring_prep_nop(sqe);
    }
    return detail::async_token_init(
        task->__M_token.emplace(detail::async_token_generate(
            task,
            [](auto& token, io_context::__task_t* self) mutable -> int {
                token(self->__M_ec);
                return 0;
            },
            std::forward<CompletionToken>(token))),
        std::forward<CompletionToken>(token));
}

template <typename CompletionToken>
decltype(auto)
chx::net::io_context::async_nop(CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::nop>()(
        this, detail::async_token_bind<const std::error_code&>(
                  std::forward<CompletionToken>(completion_token)));
}
