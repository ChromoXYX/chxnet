#pragma once

#include "../semaphore.hpp"
#include "../cancellation.hpp"

namespace chx::net::detail {
namespace tags {
struct real_semaphore {};
}  // namespace tags

template <> struct async_operation<tags::real_semaphore> {
    template <typename BindCompletionToken>
    decltype(auto) operator()(semaphore* self,
                              BindCompletionToken&& bind_completion_token) {
        auto [sqe, task] = self->get_associated_io_context().get();
        self->__M_interrupter.do_read(sqe, task);
        return async_token_init(task->__M_token.emplace(async_token_generate(
                                    task,
                                    [](auto& token, io_context::task_t* task) {
                                        io_uring_cqe* cqe = task->__M_cqe;
                                        int res = cqe->res;
                                        assert(res == 8 || res < 0);
                                        token(res == 8 ? std::error_code{}
                                                       : make_ec(-res));
                                        return 0;
                                    },
                                    bind_completion_token)),
                                bind_completion_token);
    }
};
}  // namespace chx::net::detail

template <typename CompletionToken>
decltype(auto)
chx::net::semaphore::async_acquire(CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::real_semaphore>()(
        this, detail::async_token_bind<const std::error_code&>(
                  std::forward<CompletionToken>(completion_token)));
}
