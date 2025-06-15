#pragma once

#include "./detail/tracker.hpp"
#include "./async_combine.hpp"

#include "./detail/task_carrier.hpp"

namespace chx::net {
namespace detail {
template <typename BindCompletionToken> struct cancellation_ops;
struct cancellation_assign;

namespace tags {
struct unified_cancel {};
struct cancellation_get_task {};
struct cancellation_assign {};
}  // namespace tags

template <> struct async_operation<tags::unified_cancel> {
    void cancel(io_context* ctx, io_context::task_t* task) const {
        if (!task->__M_custom_cancellation) {
            switch (task->__M_cancel_type) {
            case task_decl::__CT_io_uring_based: {
                ctx->cancel_task(task);
                break;
            }
            case task_decl::__CT_invoke_cancel: {
                task->__M_token(task);
                break;
            }
            case task_decl::__CT_no_cancel:
                break;
            }
        } else {
            task->__M_custom_cancellation->cancel(task);
        }
    }
};
}  // namespace detail
struct cancellation_signal {
    template <typename BindCompletionToken>
    friend struct detail::cancellation_ops;
    friend struct detail::cancellation_assign;
    template <typename Tag> friend struct detail::async_operation;

    cancellation_signal() = default;
    cancellation_signal(const cancellation_signal&) = default;
    cancellation_signal& operator=(const cancellation_signal&) = default;

    void emit() {
        if (__M_tracker) {
            detail::async_operation<detail::tags::unified_cancel>().cancel(
                &__M_tracker->get_associated_io_context(), __M_tracker.get());
        }
    }

    void clear() noexcept(true) { __M_tracker.release(); }
    bool valid() const noexcept(true) { return __M_tracker; }
    operator bool() const noexcept(true) { return valid(); }

  protected:
    detail::weak_ptr<io_context::task_t> __M_tracker;
    void assign(io_context::task_t* t,
                const detail::owner_guard& owner) noexcept(true) {
        __M_tracker = {t, owner};
    }
};

namespace detail {
template <> struct async_operation<tags::cancellation_get_task> {
    weak_ptr<io_context::task_t> operator()(cancellation_signal& sig) const
        noexcept(true) {
        return sig.__M_tracker;
    }
};
template <> struct async_operation<tags::cancellation_assign> {
    void operator()(cancellation_signal& sig, io_context::task_t* t,
                    const detail::owner_guard& owner) const noexcept(true) {
        sig.assign(t, owner);
    }
};

template <typename Operation, typename CompletionToken,
          typename EnableReferenceCount>
int async_combine_impl<Operation, CompletionToken,
                       EnableReferenceCount>::operator()(io_context::task_t*) {
    for (auto* task : __M_subtasks) {
        detail::async_operation<detail::tags::unified_cancel>().cancel(
            &get_associated_io_context(), task);
    }
    return 0;
}
}  // namespace detail

template <typename CompletionToken>
decltype(auto) bind_cancellation_signal(cancellation_signal& signal,
                                        CompletionToken&& completion_token) {
    return detail::task_carrier_s1(
        std::forward<CompletionToken>(completion_token), detail::owner_guard{},
        [&signal](task_decl* task, auto ti, detail::owner_guard* g) {
            detail::async_operation<detail::tags::cancellation_assign>()(
                signal, task, *g);
        });
}
}  // namespace chx::net
