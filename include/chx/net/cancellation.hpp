#pragma once

#include "./async_token.hpp"
#include "./async_combine.hpp"

namespace chx::net::detail::tags {
struct outer_cancel {};
}  // namespace chx::net::detail::tags

template <>
struct chx::net::detail::async_operation<chx::net::detail::tags::outer_cancel> {
    void normal_cancel(io_context* ctx, io_context::task_t* task) const {
        ctx->cancel_task(task);
    }
    void invoke_cancel(io_context* ctx, io_context::task_t* task) const {
        task->__M_token(task);
    }
    constexpr bool get_cancel_type(io_context::task_t* t) const noexcept(true) {
        return t->__M_cancel_invoke;
    }
};

namespace chx::net {
namespace detail {
template <typename BindCompletionToken> struct cancellation_ops;
struct cancellation_assign;

struct cancellation_base {
    virtual void operator()() = 0;
    virtual ~cancellation_base() = default;
};
}  // namespace detail
struct cancellation_signal : CHXNET_NONCOPYABLE {
    template <typename BindCompletionToken>
    friend struct detail::cancellation_ops;
    friend struct detail::cancellation_assign;
    template <typename Tag> friend struct detail::async_operation;

    cancellation_signal() = default;
    cancellation_signal(cancellation_signal&&) = default;
    cancellation_signal& operator=(cancellation_signal&&) = default;

    void emit() {
        if (__M_op) {
            (*__M_op)();
            clear();
        }
    }

    void clear() noexcept(true) { __M_op.reset(); }
    detail::cancellation_base* get() noexcept(true) { return __M_op.get(); }

    bool valid() const noexcept(true) { return __M_op.get(); }
    operator bool() const noexcept(true) { return valid(); }

  private:
    void assign(io_context::task_t* task) noexcept(true) {
        struct ops : detail::cancellation_base {
            io_context::task_t* t;
            ops(io_context::task_t* task) noexcept(true) : t(task) {}

            void operator()() override {
                detail::async_operation<detail::tags::outer_cancel>()
                    .normal_cancel(&t->get_associated_io_context(), t);
            }
        };
        struct ops2 : detail::cancellation_base {
            io_context::task_t* t;
            ops2(io_context::task_t* task) noexcept(true) : t(task) {}
            void operator()() override {
                detail::async_operation<detail::tags::outer_cancel>()
                    .invoke_cancel(&t->get_associated_io_context(), t);
            }
        };
        if (!detail::async_operation<detail::tags::outer_cancel>()
                 .get_cancel_type(task)) {
            __M_op.reset(new ops(task));
        } else {
            __M_op.reset(new ops2(task));
        }
    }
    void emplace(detail::cancellation_base* base) noexcept(true) {
        __M_op.reset(base);
    }
    std::unique_ptr<detail::cancellation_base> __M_op;
};

namespace detail {
struct cancellation_attr {};

struct cancellation_assign {
    void operator()(io_context::task_t* t,
                    cancellation_signal& s) noexcept(true) {
        s.assign(t);
    }
    void emplace(cancellation_base* base,
                 cancellation_signal& s) noexcept(true) {
        s.emplace(base);
    }
};

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
        if (task->__M_custom_cancellation) {
            assert(!task->__M_cancel_invoke);
            (*task->__M_custom_cancellation)(signal);
        } else {
            signal.assign(task);
        }
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

namespace tags {
struct async_combine_cancel_and_submit {};
}  // namespace tags

template <> struct async_operation<tags::async_combine_cancel_and_submit> {
    void cancel(io_context* ctx, io_context::task_t* task) const {
        if (!task->__M_custom_cancellation) {
            if (task->__M_cancel_invoke) {
                task->__M_token(task);
            } else {
                ctx->cancel_task(task);
            }
        } else {
            task->__M_custom_cancellation->cancel(task);
        }
    }
    void submit(io_context* ctx) const { ctx->submit(); }
};

template <typename Operation, typename CompletionToken,
          typename EnableReferenceCount>
int async_combine_impl<Operation, CompletionToken,
                       EnableReferenceCount>::operator()(io_context::task_t*) {
    for (auto* task : __M_subtasks) {
        detail::async_operation<detail::tags::async_combine_cancel_and_submit>()
            .cancel(&get_associated_io_context(), task);
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
