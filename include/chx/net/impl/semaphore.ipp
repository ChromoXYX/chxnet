#pragma once

#include "../semaphore.hpp"
#include "../cancellation.hpp"
#include "../detail/tracker.hpp"

#include <algorithm>
#include <optional>

namespace chx::net::detail {
namespace tags {
struct task_queue_tag {};
template <typename Action> struct task_queue_cncl_cntl {};
}  // namespace tags

template <> struct async_operation<tags::task_queue_tag> {
    template <typename Resource>
    struct cncl_cntl : io_context::task_t::cancellation_controller_base {
        cncl_cntl(semaphore<Resource>* q, io_context::task_t* t) noexcept(true)
            : queue(q->weak_from_this()), task(t) {}

        weak_ptr<semaphore<Resource>> queue;
        io_context::task_t* const task;

        void cancel(io_context::task_t* t) override {
            assert(t == task);
            if (valid()) {
                auto ite = std::find_if(
                    queue->__M_queue.begin(), queue->__M_queue.end(),
                    [&](const std::unique_ptr<io_context::task_t>& ptr) {
                        return ptr.get() == task;
                    });
                if (ite != queue->__M_queue.end()) {
                    try {
                        queue->__M_trash.emplace_back(std::move(*ite));
                        queue->__M_queue.erase(ite);
                        async_flush();
                    } catch (const std::exception&) {
                        rethrow_with_fatal(std::current_exception());
                    }
                }
                exclude();
            }
        }

        constexpr bool valid() noexcept(true) { return !queue.expired(); }
        constexpr void exclude() noexcept(true) { queue.release(); }

        void async_flush() {
            if (valid() && !queue->__M_flushing) {
                queue->__M_flushing = true;
                task->__M_ctx->async_nop([guard = queue->weak_from_this()](
                                             const std::error_code&) {
                    if (!guard.expired()) {
                        guard->__M_flushing = false;
                        std::vector<std::unique_ptr<io_context::task_t>> trash =
                            std::move(guard->__M_trash);
                        for (auto& ptr : trash) {
                            ptr->__M_res = ECANCELED;
                            ptr->__M_token(ptr.get());
                        }
                    }
                });
            }
        }
    };

    template <typename Resource, typename BindCompletionToken>
    decltype(auto) push(semaphore<Resource>* self,
                        BindCompletionToken&& bind_completion_token) {
        io_context::task_t* task =
            self->__M_queue
                .emplace_back(std::make_unique<io_context::task_t>(
                    &self->get_associated_io_context()))
                .get();

        if (self->__M_res_queue.empty()) {
            task->__M_custom_cancellation =
                std::make_unique<cncl_cntl<Resource>>(self, task);
        } else {
            task->__M_cancel_type = task->__CT_no_cancel;
            auto res = std::move(self->__M_res_queue.back());
            self->__M_res_queue.pop();
            self->release(std::move(res));
        }

        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* task) {
                    int res = task->__M_res;
                    token(res == 0 ? std::error_code{} : make_ec(res),
                          res == 0 ? std::optional<Resource>(
                                         std::move(*reinterpret_cast<Resource*>(
                                             task->__M_additional)))
                                   : std::nullopt);
                    return 0;
                },
                std::forward<BindCompletionToken>(bind_completion_token))),
            std::forward<BindCompletionToken>(bind_completion_token));
    }
};
}  // namespace chx::net::detail

template <typename Resource>
template <typename CompletionToken>
decltype(auto) chx::net::semaphore<Resource>::async_acquire(
    CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::task_queue_tag>().push(
        this, detail::async_token_bind<const std::error_code&,
                                       std::optional<Resource>>(
                  std::forward<CompletionToken>(completion_token)));
}
