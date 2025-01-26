#pragma once

#include "../io_context.hpp"
#include "../detail/io_uring_task_getter.hpp"

namespace chx::net::detail {
namespace tags {
struct async_close {};
}  // namespace tags

template <> struct async_operation<tags::async_close> {
    template <typename Stream, typename CompletionToken>
    decltype(auto) operator()(io_context* ctx, Stream* stream,
                              CompletionToken&& completion_token) {
        auto [sqe, task] = ctx->get();
        io_uring_prep_close(sqe, stream->native_handler());
        task->__M_additional = reinterpret_cast<std::uint64_t>(stream);
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) -> int {
                    Stream* stream =
                        reinterpret_cast<Stream*>(self->__M_additional);
                    auto ec = get_ec(self);
                    if (ec != errc::operation_canceled) {
                        stream->__M_fd = -1;
                    }
                    token(ec);
                    return 0;
                },
                completion_token)),
            completion_token);
    }
};
}  // namespace chx::net::detail
