#pragma once

#include "../async_recvmsg.hpp"
#include "../async_operation.hpp"
#include "../io_context.hpp"
#include "../async_token.hpp"
#include "../detail/task_carrier.hpp"

namespace chx::net::detail {
namespace tags {
struct recvmsg {};
}  // namespace tags

template <> struct async_operation<tags::recvmsg> {
    template <typename Socket, typename BindCompletionToken>
    decltype(auto) recvmsg(Socket& socket, msghdr& msghdr,
                           BindCompletionToken&& bind_completion_token) {
        auto carrier = task_carrier_s2(
            std::forward<BindCompletionToken>(bind_completion_token), msghdr,
            [&socket](task_decl* task, auto ti, struct msghdr* msghdr) {
                io_context* ctx = &task->get_associated_io_context();
                io_uring_sqe* sqe = ctx->get_sqe(task);
                io_uring_prep_recvmsg(sqe, socket.native_handler(), msghdr, 0);
            });

        task_decl* task = socket.get_associated_io_context().acquire();
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, task_decl* self) -> int {
                    const io_uring_cqe* cqe = self->__M_cqe;
                    const int res = cqe->res;
                    token(res >= 0 ? std::error_code{} : make_ec(-res), res);
                    return 0;
                },
                carrier)),
            carrier);
    }
};
}  // namespace chx::net::detail

template <typename Socket, typename CompletionToken>
decltype(auto) chx::net::async_recvmsg(Socket& socket, msghdr& msghdr,
                                       CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::recvmsg>().recvmsg(
        socket, msghdr,
        detail::async_token_bind<const std::error_code&, std::size_t>(
            std::forward<CompletionToken>(completion_token)));
}
