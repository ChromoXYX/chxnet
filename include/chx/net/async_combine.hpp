#pragma once

#include "./io_context.hpp"
#include "./async_token.hpp"
#include "./attribute.hpp"
#include "./detail/task_aware.hpp"

#include <algorithm>

namespace chx::net {
namespace detail {
namespace tags {
struct async_combine_persist {};
struct async_combine_cancel_and_submit {};
}  // namespace tags
template <> struct async_operation<tags::async_combine_persist> {
    void operator()(io_context::task_t* task) noexcept(true) {
        if (task->__M_releasable) {
            task->get_associated_io_context().release(task);
        }
    }
};

template <> struct async_operation<tags::async_combine_cancel_and_submit> {
    void cancel(io_context* ctx, io_context::task_t* task) const {
        if (!task->__M_cancel_invoke) {
            ctx->cancel_task(task);
        } else {
            task->__M_token(task);
        }
    }
    void submit(io_context* ctx) { ctx->submit(); }
};

template <typename Operation, typename CompletionToken>
struct async_combine_impl : Operation, CompletionToken, CHXNET_NONCOPYABLE {
    using attribute_type = attribute<async_token>;

    io_context::task_t* const __M_associated_task;
    std::vector<io_context::task_t*> __M_subtasks;

    template <typename Op, typename C>
    constexpr async_combine_impl(io_context::task_t* task, Op&& op, C&& c)
        : __M_associated_task(task), Operation(std::forward<Op>(op)),
          CompletionToken(std::forward<C>(c)) {
        // may be dangerous?
        // if async_combine is cancelled, would async_nop invoke it?
        // may not, since when token_storage is destructing, the inner functor
        // will not be invoked. and at this time, async_combine cannot be
        // cancelled by io_uring.
        // __M_associated_task->get_associated_io_context().async_nop(next());
        direct_invoke(std::error_code{});
    }

    int operator()(io_context::task_t*) {
        for (auto t : __M_subtasks) {
            async_operation<tags::async_combine_cancel_and_submit>().cancel(
                &get_associated_io_context(), t);
        }
        async_operation<tags::async_combine_cancel_and_submit>().submit(
            &get_associated_io_context());
        return 0;
    }

    constexpr io_context& get_associated_io_context() noexcept(true) {
        return get_associated_task()->get_associated_io_context();
    }
    constexpr io_context::task_t* get_associated_task() noexcept(true) {
        return __M_associated_task;
    }
    constexpr CompletionToken& get_completion_token() noexcept(true) {
        return *this;
    }
    template <typename... Ts> decltype(auto) complete(Ts&&... ts) {
        if (!__M_subtasks.empty()) {
            __CHXNET_THROW(EINVAL);
        }
        CompletionToken::operator()(std::forward<Ts>(ts)...);
        async_operation<tags::async_combine_persist>()(get_associated_task());
    }
    template <typename Func> void async_nop(Func&& func) {
        __M_associated_task->get_associated_io_context().async_nop(
            [this, func = std::forward<Func>(func)](
                const std::error_code& ec) mutable { func(*this, ec); });
    }

    template <typename... Ts> decltype(auto) direct_invoke(Ts&&... ts) {
        return Operation::operator()(*this, std::forward<Ts>(ts)...);
    }

    struct next_guard : CHXNET_NONCOPYABLE {
        async_combine_impl* self;
        io_context::task_t* task = nullptr;

        constexpr next_guard(async_combine_impl* ptr) noexcept(true)
            : self(ptr) {}
        constexpr next_guard(next_guard&& other) noexcept(true)
            : self(other.self), task(other.task) {
            other.self = nullptr;
            other.task = nullptr;
        }

        void aware(io_context::task_t* t) {
            task = t;
            self->__M_subtasks.push_back(t);
        }
        template <typename... Ts> void operator()(Ts&&... ts) {
            release_and_remove();
            self->direct_invoke(std::forward<Ts>(ts)...);
        }

        void release_and_remove() {
            assert(task);
            self->__M_subtasks.erase(std::find(self->__M_subtasks.begin(),
                                               self->__M_subtasks.end(), task));
            task = nullptr;
        }
        ~next_guard() {
            if (task) {
                self->__M_subtasks.erase(std::find(self->__M_subtasks.begin(),
                                                   self->__M_subtasks.end(),
                                                   task));
            }
        }
    };

    constexpr auto next() noexcept(true) {
        return task_aware(next_guard(this));
    }
};
template <typename Operation, typename CompletionToken>
async_combine_impl(io_context::task_t*, Operation&&, CompletionToken&&)
    -> async_combine_impl<std::remove_reference_t<Operation>,
                          std::remove_reference_t<CompletionToken>>;

namespace tags {
struct combine {};
}  // namespace tags

template <> struct async_operation<tags::combine> {
    template <typename Operation, typename CompletionToken>
    decltype(auto) operator()(io_context& ctx, Operation&& operation,
                              CompletionToken&& completion_token) {
        io_context::task_t* task = ctx.acquire();

        task->__M_persist = true;
        task->__M_cancel_invoke = true;
        using __ctad_type = decltype(detail::async_combine_impl(
            task, std::forward<Operation>(operation),
            std::move(detail::async_token_generate(
                task, __CHXNET_FAKE_FINAL_FUNCTOR(),
                completion_token)(nullptr))));
        return detail::async_token_init(
            task->__M_token.emplace<__ctad_type>(
                detail::inplace, task, std::forward<Operation>(operation),
                std::move(detail::async_token_generate(
                    task, __CHXNET_FAKE_FINAL_FUNCTOR(),
                    completion_token)(nullptr))),
            completion_token);
    }
};

}  // namespace detail

/**
 * @brief Helper method to combine multiple async tasks.
 *
 * @note complete() method can only be called once, and only when there is no
 * outstanding async tasks that were submitted by the operation before.
 *
 * @tparam Signature Parameters of the signature of completion_token.
 * @param ctx io_context which will handles the combined async task.
 * @param op Callable object which implements the operations.
 * @param completion_token Callable object which will be called when the
 * combined async tasks completed.
 * @return decltype(auto)
 */
template <typename... Signature, typename Operation, typename CompletionToken>
decltype(auto) async_combine(io_context& ctx, Operation&& op,
                             CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::combine>()(
        ctx, std::forward<Operation>(op),
        detail::async_token_bind<Signature...>(
            std::forward<CompletionToken>(completion_token)));
}
}  // namespace chx::net
