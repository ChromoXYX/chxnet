#pragma once

#include "../semaphore.hpp"
#include "../cancellation.hpp"
#include "../detail/tracker.hpp"

#include <algorithm>

namespace chx::net::detail {
namespace tags {
struct task_queue_tag {};
template <typename Action> struct task_queue_cncl_cntl {};
}  // namespace tags

template <> struct async_operation<tags::task_queue_tag> {
    struct cncl_cntl : io_context::task_t::cancellation_controller_base,
                       enable_weak_from_this<cncl_cntl> {
        cncl_cntl(semaphore* q, io_context::task_t* t) noexcept(true)
            : queue(q->weak_from_this()), task(t) {}

        weak_ptr<semaphore> queue;
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
                    assign_ec(task->__M_ec, errc::operation_canceled);
                    queue->__M_trash.emplace_back(std::move(*ite));
                    queue->__M_queue.erase(ite);
                    async_flush();
                }
                exclude();
            }
        }

        constexpr bool valid() noexcept(true) { return !queue.expired(); }
        constexpr void exclude() noexcept(true) { queue.release(); }

        struct cncl : cancellation_base {
            weak_ptr<cncl_cntl> controller;

            cncl(cncl_cntl* cntl) : controller(cntl->weak_from_this()) {}

            constexpr bool valid() noexcept(true) {
                return !controller.expired() && controller->valid();
            }

            void operator()() override {
                if (valid()) {
                    controller->cancel(controller->task);
                }
            }
        };

        void operator()(cancellation_signal& signal) override {
            if (valid()) {
                signal.emplace(new cncl(this));
            }
        }

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
                            ptr->__M_token(ptr.get());
                        }
                    }
                });
            }
        }
    };

    template <typename BindCompletionToken>
    decltype(auto) push(semaphore* self,
                        BindCompletionToken&& bind_completion_token) {
        io_context::task_t* task =
            self->__M_queue
                .emplace_back(std::make_unique<io_context::task_t>(
                    &self->get_associated_io_context()))
                .get();
        task->__M_custom_cancellation.reset(new cncl_cntl(self, task));

        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* task) {
                    token(task->__M_ec);
                    return 0;
                },
                std::forward<BindCompletionToken>(bind_completion_token))),
            std::forward<BindCompletionToken>(bind_completion_token));
    }
};
}  // namespace chx::net::detail

template <typename CompletionToken>
decltype(auto)
chx::net::semaphore::async_acquire(CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::task_queue_tag>().push(
        this, detail::async_token_bind<const std::error_code&>(
                  std::forward<CompletionToken>(completion_token)));
}
