#pragma once

#include "../basic_fixed_timer.hpp"

namespace chx::net {
template <typename Timer>
struct fixed_timer_cancellation : detail::cancellation_base {
    Timer* timer;
    std::chrono::time_point<std::chrono::system_clock> tp;
    io_context::task_t* task;

    using container_type = decltype(timer->__M_set);

    fixed_timer_cancellation(
        Timer* t, std::chrono::time_point<std::chrono::system_clock> k,
        io_context::task_t* v) noexcept(true)
        : timer(t), tp(k), task(v) {}

    constexpr void release() noexcept(true) {
        timer = nullptr;
        task = nullptr;
    }
    constexpr bool valid() noexcept(true) {
        return timer != nullptr && task != nullptr;
    }

    void operator()() override {
        if (auto ite = find_position(); ite != timer->__M_set.end()) {
            task->__M_token(task);
            timer->__M_set.erase(ite);
            release();
        }
    }

    typename container_type::iterator find_position() noexcept(true) {
        auto [begin, end] = timer->__M_set.equal_range(tp);
        for (auto ite = begin; ite != end; ++ite) {
            if (ite->second.get() == task) {
                return ite;
            }
        }
        return timer->__M_set.end();
    }

    void
    update(const std::chrono::time_point<std::chrono::system_clock>& new_tp) {
        try {
            typename container_type::node_type node =
                timer->__M_set.extract(find_position());
            node.key() = new_tp;
            timer->__M_set.insert(std::move(node));
            tp = new_tp;
        } catch (...) {
            release();
            std::rethrow_exception(std::current_exception());
        }
    }

    template <typename Rep, typename Period>
    void update(const std::chrono::duration<Rep, Period>& dur) {
        update(std::chrono::system_clock::now() + dur);
    }
};
}  // namespace chx::net

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
        Timer* timer,
        const std::chrono::time_point<std::chrono::system_clock, Duration>& tp,
        wrapper<BindCompletionToken>&& wrapper) {

        auto ite = timer->__M_set.insert(std::make_pair(
            tp, std::make_unique<io_context::task_t>(timer->__M_ctx)));
        io_context::task_t* task = ite->second.get();
        task->__M_avail = true;
        task->__M_cancel_invoke = true;
        task->__M_option5 = false;
        task->__M_additional = reinterpret_cast<std::uint64_t>(timer);

        wrapper.signal.emplace(new fixed_timer_cancellation(timer, tp, task));

        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) mutable {
                    assert(self);
                    if (self->__M_option5) {
                        token(std::error_code{});
                    } else {
                        auto* timer =
                            reinterpret_cast<Timer*>(self->__M_additional);
                        token(make_ec(errc::operation_canceled));
                    }
                    return 0;
                },
                std::forward<BindCompletionToken>(
                    wrapper.bind_completion_token))),
            std::forward<BindCompletionToken>(wrapper.bind_completion_token));
    }

    template <typename Timer, typename Duration, typename BindCompletionToken>
    decltype(auto) operator()(
        Timer* timer,
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
                [](auto& token, io_context::task_t* self) mutable {
                    assert(self);
                    if (self->__M_option5) {
                        token(std::error_code{});
                    } else {
                        auto* timer =
                            reinterpret_cast<Timer*>(self->__M_additional);
                        token(make_ec(errc::operation_canceled));
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
    if constexpr (!check_attr<detail::cancellation_attr,
                              std::decay_t<CompletionToken>>()) {
        return detail::async_operation<detail::tags::fixed_timer>()(
            this, std::chrono::system_clock::now() + dur,
            detail::async_token_bind<const std::error_code&>(
                std::forward<CompletionToken>(completion_token)));
    } else {
        return detail::async_operation<detail::tags::fixed_timer>()(
            this, std::chrono::system_clock::now() + dur,
            detail::async_operation<detail::tags::fixed_timer>::wrapper(
                detail::async_token_bind<const std::error_code&>(
                    std::move(completion_token.noref_completion_token)),
                completion_token.signal));
    }
}

template <typename Rep, typename Period, typename CompletionToken>
decltype(auto) chx::net::fixed_timeout_timer::async_register(
    const std::chrono::duration<Rep, Period>& dur,
    CompletionToken&& completion_token) {
    if constexpr (!check_attr<detail::cancellation_attr,
                              std::decay_t<CompletionToken>>()) {
        return detail::async_operation<detail::tags::fixed_timer>()(
            this, std::chrono::system_clock::now() + dur,
            detail::async_token_bind<const std::error_code&>(
                std::forward<CompletionToken>(completion_token)));
    } else {
        return detail::async_operation<detail::tags::fixed_timer>()(
            this, std::chrono::system_clock::now() + dur,
            detail::async_operation<detail::tags::fixed_timer>::wrapper(
                detail::async_token_bind<const std::error_code&>(
                    std::move(completion_token.noref_completion_token)),
                completion_token.signal));
    }
}

void chx::net::fixed_timeout_timer::listen() {
    async_timeout(
        get_associated_io_context(), __M_interval,
        bind_cancellation_signal(__M_signal, [&](const std::error_code& e) {
            if (!e) {
                auto curr = std::chrono::system_clock::now();
                for (auto& [k, v] : __M_set) {
                    if (k < curr) {
                        v->__M_option5 = true;
                        v->__M_token(v.get());
                    } else {
                        break;
                    }
                }
                __M_set.erase(__M_set.begin(), __M_set.lower_bound(curr));
                listen();
            }
        }));
}
