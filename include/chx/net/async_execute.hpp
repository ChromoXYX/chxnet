#pragma once

#include "./io_context.hpp"
#include <exception>
#include <future>

namespace chx::net {
namespace detail {
namespace tags {
struct async_execute {};
}  // namespace tags

template <> struct async_operation<tags::async_execute> {
    template <typename RetType> struct operation {
        template <typename Executor, typename Fn, typename BindCompletionToken>
        decltype(auto) f(io_context* from, Executor* to, Fn&& fn,
                         BindCompletionToken&& bind_completion_token) {
            using __decay_t = std::decay_t<Fn>;
            io_context::task_t* const task = from->acquire();
            task->__M_cancel_type = task->__CT_no_cancel;

            std::promise<RetType> promise;
            std::future future = promise.get_future();
            to->post([fn = std::forward<Fn>(fn), self = task,
                      promise = std::move(promise)]() mutable {
                try {
                    if constexpr (!std::is_same_v<RetType, void> &&
                                  !std::is_same_v<RetType, const void>) {
                        promise.set_value(std::forward<Fn>(fn)());
                    } else {
                        std::forward<Fn>(fn)();
                        promise.set_value();
                    }
                } catch (...) {
                    promise.set_exception(std::current_exception());
                }
                io_context* const from = &self->get_associated_io_context();
                from->post([self](io_context* from) mutable {
                    self->__M_token(self);
                    from->release(self);
                });
                from->interrupt();
            });
            to->interrupt();
            return async_token_init(
                task->__M_token.emplace(async_token_generate(
                    task,
                    [future = std::move(future)](
                        auto& token, io_context::task_t* self) mutable {
                        token(std::error_code{}, std::move(future));
                        return 0;
                    },
                    bind_completion_token)),
                bind_completion_token);
        }
    };
};
}  // namespace detail

template <typename Executor, typename Fn, typename CompletionToken>
decltype(auto) async_execute(io_context& from, Executor& to, Fn&& fn,
                             CompletionToken&& completion_token) {
    using ret_type = std::invoke_result_t<Fn&&>;
    return detail::async_operation<detail::tags::async_execute>::operation<
               ret_type>()
        .f(&from, &to, std::forward<Fn>(fn),
           detail::async_token_bind<const std::error_code&,
                                    std::future<ret_type>>(
               std::forward<CompletionToken>(completion_token)));
}
}  // namespace chx::net
