#pragma once

#include "./async_token.hpp"
#include "./async_combine.hpp"

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
            case task_declare::task_decl::__CT_io_uring_based: {
                ctx->cancel_task(task);
                break;
            }
            case task_declare::task_decl::__CT_invoke_cancel: {
                task->__M_token(task);
                break;
            }
            case task_declare::task_decl::__CT_no_cancel:
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
    void assign(io_context::task_t* t) noexcept(true) {
        __M_tracker = t->weak_from_this();
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
    void operator()(cancellation_signal& sig, io_context::task_t* t) const
        noexcept(true) {
        sig.assign(t);
    }
};

struct cancellation_attr {};
template <typename BindCompletionToken> struct cancellation_ops {
    using attribute_type = attribute<async_token, cancellation_attr>;

    BindCompletionToken bind_completion_token;
    cancellation_signal& signal;

    template <typename BCT>
    constexpr cancellation_ops(cancellation_signal& s, BCT&& bct) noexcept(true)
        : signal(s), bind_completion_token(std::forward<BCT>(bct)) {}

    template <typename FinalFunctor>
    decltype(auto) generate_token(io_context::task_t* task,
                                  FinalFunctor&& final_functor) {
        signal.assign(task);
        return async_token_generate(task,
                                    std::forward<FinalFunctor>(final_functor),
                                    bind_completion_token);
    }
    template <typename T> decltype(auto) get_init(T t) {
        return async_token_init(t, bind_completion_token);
    }
};
template <typename BindCompletionToken>
cancellation_ops(cancellation_signal&, BindCompletionToken&&)
    -> cancellation_ops<std::remove_reference_t<BindCompletionToken>>;

template <typename NoRefCompletionToken> struct cancellation_inter {
    using attribute_type = attribute<async_token, cancellation_attr>;

    NoRefCompletionToken noref_completion_token;
    cancellation_signal& signal;

    template <typename RCT>
    constexpr cancellation_inter(cancellation_signal& s,
                                 RCT&& rct) noexcept(true)
        : signal(s), noref_completion_token(std::forward<RCT>(rct)) {}

    template <typename... S> decltype(auto) bind() {
        return cancellation_ops(
            signal, async_token_bind<S...>(std::move(noref_completion_token)));
    }
};
template <typename RefCompletionToken>
cancellation_inter(cancellation_signal&, RefCompletionToken&&)
    -> cancellation_inter<std::remove_reference_t<RefCompletionToken>>;

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
    return detail::cancellation_inter(
        signal, std::forward<CompletionToken>(completion_token));
}
}  // namespace chx::net
