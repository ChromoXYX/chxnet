#pragma once

#if CHXNET_KERNEL_VERSION_MAJOR < 5
#warning chxnet cancellation for single async task requires at least kernel version 5.19
#else
#if CHXNET_KERNEL_VERSION_MAJOR == 5 && CHXNET_KERNEL_VERSION_MINOR < 19
#warning chxnet cancellation for single async task requires at least kernel version 5.19
#endif
#endif

#include "./async_token.hpp"

namespace chx::net::detail::tags {
struct outer_cancel {};
}  // namespace chx::net::detail::tags

template <>
struct chx::net::detail::async_operation<chx::net::detail::tags::outer_cancel> {
    void cancel(io_context* ctx, io_context::task_t* task) const {
        if (!task->__M_cancel_invoke) {
            ctx->cancel_task(task);
        } else {
            task->__M_token(task);
        }
    }
};

namespace chx::net {
namespace detail {
template <typename BindCompletionToken> struct cancellation_ops;
}
struct cancellation_signal {
    template <typename BindCompletionToken>
    friend struct detail::cancellation_ops;

    void emit() {
        if (__M_task) {
            detail::async_operation<detail::tags::outer_cancel>().cancel(
                &__M_task->get_associated_io_context(), __M_task);
        }
    }

    constexpr void clear() noexcept(true) { __M_task = nullptr; }

  private:
    constexpr void assign(io_context::task_t* task) noexcept(true) {
        __M_task = task;
    }
    io_context::task_t* __M_task = nullptr;
};

namespace detail {
template <typename BindCompletionToken> struct cancellation_ops {
    using attribute_type = attribute<async_token>;

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

template <typename RefCompletionToken> struct cancellation_inter {
    using attribute_type = attribute<async_token>;

    RefCompletionToken ref_completion_token;
    cancellation_signal& signal;

    template <typename RCT>
    constexpr cancellation_inter(cancellation_signal& s,
                                 RCT&& rct) noexcept(true)
        : signal(s), ref_completion_token(std::forward<RCT>(rct)) {}

    template <typename... S> decltype(auto) bind() {
        return cancellation_ops(signal,
                                async_token_bind<S...>(ref_completion_token));
    }
};
template <typename RefCompletionToken>
cancellation_inter(cancellation_signal&, RefCompletionToken&&)
    -> cancellation_inter<RefCompletionToken&&>;
}  // namespace detail

template <typename CompletionToken>
decltype(auto) bind_cancellation_signal(cancellation_signal& signal,
                                        CompletionToken&& completion_token) {
    return detail::cancellation_inter(
        signal, std::forward<CompletionToken>(completion_token));
}
}  // namespace chx::net
