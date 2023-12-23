#pragma once

#include "../basic_fixed_timer.hpp"

namespace chx::net::detail {
template <> struct async_operation<tags::fixed_timer> {
    template <typename BindCompletionToken> struct wrapper {
        BindCompletionToken bind_completion_token;
        cancellation_signal& signal;

        template <typename BCT>
        wrapper(BCT&& bct, cancellation_signal& s)
            : bind_completion_token(std::forward<BCT>(bct)), signal(s) {}
    };
    template <typename BindCompletionToken>
    wrapper(BindCompletionToken&&, cancellation_signal&)
        -> wrapper<std::remove_reference_t<BindCompletionToken>>;

    template <typename Timer, typename Duration, typename BindCompletionToken>
    decltype(auto) operator()(
        basic_fixed_timer<Timer>* timer,
        const std::chrono::time_point<std::chrono::system_clock, Duration>& tp,
        wrapper<BindCompletionToken>&& wrapper) {

        auto ite = timer->__M_set.insert(std::make_pair(
            tp, std::make_unique<io_context::task_t>(timer->__M_ctx)));
        io_context::task_t* task = ite->second.get();
        task->__M_avail = true;
        task->__M_cancel_invoke = true;
        task->__M_option5 = false;
        task->__M_additional = reinterpret_cast<std::uint64_t>(timer);

        struct c : cancellation_base {
            basic_fixed_timer<Timer>* timer;
            std::chrono::time_point<std::chrono::system_clock> tp;
            io_context::task_t* task;

            c(basic_fixed_timer<Timer>* t,
              std::chrono::time_point<std::chrono::system_clock> k,
              io_context::task_t* v) noexcept(true)
                : timer(t), tp(k), task(v) {}

            void operator()() {
                auto [begin, end] = timer->__M_set.equal_range(tp);
                for (auto ite = begin; ite != end; ++ite) {
                    if (ite->second.get() == task) {
                        task->__M_token(task);
                        return;
                    }
                }
            }
        };
        wrapper.signal.emplace(new c(timer, tp, task));

        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [ite](auto& token, io_context::task_t* self) mutable {
                    assert(self);
                    if (self->__M_option5) {
                        token(std::error_code{});
                    } else {
                        auto* timer =
                            reinterpret_cast<basic_fixed_timer<Timer>*>(
                                self->__M_additional);
                        token(make_ec(errc::operation_canceled));
                        timer->__M_set.erase(ite);
                    }
                    return 0;
                },
                std::forward<BindCompletionToken>(
                    wrapper.bind_completion_token))),
            std::forward<BindCompletionToken>(wrapper.bind_completion_token));
    }

    template <typename Timer, typename Duration, typename BindCompletionToken>
    decltype(auto) operator()(
        basic_fixed_timer<Timer>* timer,
        const std::chrono::time_point<std::chrono::system_clock, Duration>& tp,
        BindCompletionToken&& bind_completion_token) {

        auto ite = timer->__M_set.insert(std::make_pair(
            tp, std::make_unique<io_context::task_t>(timer->__M_ctx)));
        io_context::task_t* task = ite->second.get();
        task->__M_avail = true;
        task->__M_cancel_invoke = true;
        task->__M_option5 = false;
        task->__M_additional = reinterpret_cast<std::uint64_t>(timer);
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [ite](auto& token, io_context::task_t* self) mutable {
                    assert(self);
                    if (self->__M_option5) {
                        token(std::error_code{});
                    } else {
                        auto* timer =
                            reinterpret_cast<basic_fixed_timer<Timer>*>(
                                self->__M_additional);
                        token(make_ec(errc::operation_canceled));
                        timer->__M_set.erase(ite);
                    }
                    return 0;
                },
                std::forward<BindCompletionToken>(bind_completion_token))),
            std::forward<BindCompletionToken>(bind_completion_token));
    }

    template <typename T> struct is_wrapper : std::false_type {};
    template <typename C> struct is_wrapper<wrapper<C>> : std::true_type {};
};

template <> struct async_operation<tags::fixed_timeout_timer> {
    template <typename BindCompletionToken> struct wrapper {
        BindCompletionToken bind_completion_token;
        cancellation_signal& signal;

        template <typename BCT>
        wrapper(BCT&& bct, cancellation_signal& s)
            : bind_completion_token(std::forward<BCT>(bct)), signal(s) {}
    };
    template <typename BindCompletionToken>
    wrapper(BindCompletionToken&&, cancellation_signal&)
        -> wrapper<std::remove_reference_t<BindCompletionToken>>;

    template <typename Duration, typename BindCompletionToken>
    decltype(auto) operator()(
        fixed_timeout_timer* timer,
        const std::chrono::time_point<std::chrono::system_clock, Duration>& tp,
        wrapper<BindCompletionToken>&& wrapper) {

        auto ite = timer->__M_set.insert(std::make_pair(
            tp, std::make_unique<io_context::task_t>(timer->__M_ctx)));
        io_context::task_t* task = ite->second.get();
        task->__M_avail = true;
        task->__M_cancel_invoke = true;
        task->__M_option5 = false;
        task->__M_additional = reinterpret_cast<std::uint64_t>(timer);

        struct c : cancellation_base {
            fixed_timeout_timer* timer;
            std::chrono::time_point<std::chrono::system_clock> tp;
            io_context::task_t* task;

            c(fixed_timeout_timer* t,
              std::chrono::time_point<std::chrono::system_clock> k,
              io_context::task_t* v) noexcept(true)
                : timer(t), tp(k), task(v) {}

            void operator()() {
                auto [begin, end] = timer->__M_set.equal_range(tp);
                for (auto ite = begin; ite != end; ++ite) {
                    if (ite->second.get() == task) {
                        task->__M_token(task);
                        return;
                    }
                }
            }
        };
        wrapper.signal.emplace(new c(timer, tp, task));

        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [ite](auto& token, io_context::task_t* self) mutable {
                    assert(self);
                    if (self->__M_option5) {
                        token(std::error_code{});
                    } else {
                        auto* timer = reinterpret_cast<fixed_timeout_timer*>(
                            self->__M_additional);
                        token(make_ec(errc::operation_canceled));
                        timer->__M_set.erase(ite);
                    }
                    return 0;
                },
                std::forward<BindCompletionToken>(
                    wrapper.bind_completion_token))),
            std::forward<BindCompletionToken>(wrapper.bind_completion_token));
    }

    template <typename Duration, typename BindCompletionToken>
    decltype(auto) operator()(
        fixed_timeout_timer* timer,
        const std::chrono::time_point<std::chrono::system_clock, Duration>& tp,
        BindCompletionToken&& bind_completion_token) {

        auto ite = timer->__M_set.insert(std::make_pair(
            tp, std::make_unique<io_context::task_t>(timer->__M_ctx)));
        io_context::task_t* task = ite->second.get();
        task->__M_avail = true;
        task->__M_cancel_invoke = true;
        task->__M_option5 = false;
        task->__M_additional = reinterpret_cast<std::uint64_t>(timer);
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [ite](auto& token, io_context::task_t* self) mutable {
                    assert(self);
                    if (self->__M_option5) {
                        token(std::error_code{});
                    } else {
                        auto* timer = reinterpret_cast<fixed_timeout_timer*>(
                            self->__M_additional);
                        token(make_ec(errc::operation_canceled));
                        timer->__M_set.erase(ite);
                    }
                    return 0;
                },
                std::forward<BindCompletionToken>(bind_completion_token))),
            std::forward<BindCompletionToken>(bind_completion_token));
    }

    template <typename T> struct is_wrapper : std::false_type {};
    template <typename C> struct is_wrapper<wrapper<C>> : std::true_type {};
};
}  // namespace chx::net::detail

template <typename Timer>
template <typename Rep, typename Period, typename CompletionToken>
decltype(auto) chx::net::basic_fixed_timer<Timer>::async_register(
    const std::chrono::duration<Rep, Period>& dur,
    CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::fixed_timer>()(
        this, std::chrono::system_clock::now() + dur,
        detail::async_token_bind<const std::error_code&>(
            std::forward<CompletionToken>(completion_token)));
}

template <typename Timer>
template <typename CompletionToken>
decltype(auto) chx::net::basic_fixed_timer<Timer>::bind_cancellation_signal(
    cancellation_signal& signal, CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::fixed_timer>::wrapper(
        detail::async_token_bind<const std::error_code&>(
            std::forward<CompletionToken>(completion_token)),
        signal);
}

template <typename Rep, typename Period, typename CompletionToken>
decltype(auto) chx::net::fixed_timeout_timer::async_register(
    const std::chrono::duration<Rep, Period>& dur,
    CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::fixed_timeout_timer>()(
        this, std::chrono::system_clock::now() + dur,
        detail::async_token_bind<const std::error_code&>(
            std::forward<CompletionToken>(completion_token)));
}

template <typename CompletionToken>
decltype(auto) chx::net::fixed_timeout_timer::bind_cancellation_signal(
    cancellation_signal& signal, CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::fixed_timeout_timer>::wrapper(
        detail::async_token_bind<const std::error_code&>(
            std::forward<CompletionToken>(completion_token)),
        signal);
}
