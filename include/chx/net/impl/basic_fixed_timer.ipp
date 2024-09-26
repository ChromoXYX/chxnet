#pragma once

#include "../basic_fixed_timer.hpp"

namespace chx::net {
namespace detail {
namespace tags {
struct fxd_tmr_cncl_cntl {};
}  // namespace tags
template <> struct async_operation<tags::fxd_tmr_cncl_cntl> {
    template <typename Timer> struct controller;
    template <typename Timer> struct fxd_tmr_cncl : detail::cancellation_base {
        weak_ptr<controller<Timer>> controller_;

        Timer& timer() { return *controller_->timer; }
        io_context::task_t* task() { return controller_->task; }

        fxd_tmr_cncl(controller<Timer>* p) : controller_(p->weak_from_this()) {}
        virtual ~fxd_tmr_cncl() {}

        constexpr void release() noexcept(true) { controller_.release(); }

        constexpr bool controller_valid() noexcept(true) {
            return !controller_.expired();
        }
        constexpr bool timer_valid() noexcept(true) {
            return controller_valid() && controller_->timer_valid();
        }
        constexpr bool valid() noexcept(true) { return timer_valid(); }

        void operator()() override {
            if (valid()) {
                controller_->cancel(task());
            }
        }

        void update(
            const std::chrono::time_point<std::chrono::system_clock>& new_tp) {
            controller_->update(new_tp);
        }

        template <typename Rep, typename Period>
        void update(const std::chrono::duration<Rep, Period>& dur) {
            controller_->update(dur);
        }

        constexpr auto time_point() noexcept(true) {
            return controller_->time_point;
        }
    };

    template <typename Timer>
    struct controller : io_context::task_t::cancellation_controller_base,
                        enable_weak_from_this<controller<Timer>> {
        weak_ptr<Timer> timer;
        io_context::task_t* const task;
        std::chrono::time_point<std::chrono::system_clock> time_point;

        controller(Timer* t, io_context::task_t* t2,
                   const std::chrono::time_point<std::chrono::system_clock>& tp)
            : timer(t->weak_from_this()), task(t2), time_point(tp) {}

        constexpr void exclude() noexcept(true) { timer.release(); }
        constexpr bool timer_valid() noexcept(true) { return !timer.expired(); }

        virtual ~controller() {}

        void operator()(cancellation_signal& signal) override {
            if (timer_valid()) {
                signal.emplace(new fxd_tmr_cncl<Timer>(this));
            }
        }

        void cancel(io_context::task_t* t) override {
            if (timer_valid()) {
                assert(t == task);
                auto pos = find_position();
                if (pos != timer->__M_set.end()) {
                    assign_ec(task->__M_ec, errc::operation_canceled);
                    try {
                        timer->__M_trash.emplace_back(
                            std::move(timer->__M_set.extract(pos).mapped()));
                    } catch (const std::exception& e) {
                        rethrow_with_fatal(std::current_exception());
                    }
                }
                exclude();
            }
        }

        auto find_position() noexcept(true) {
            auto [begin, end] = timer->__M_set.equal_range(time_point);
            for (auto ite = begin; ite != end; ++ite) {
                if (ite->second.get() == task) {
                    return ite;
                }
            }
            return timer->__M_set.end();
        }

        void update(
            const std::chrono::time_point<std::chrono::system_clock>& new_tp) {
            auto node = timer->__M_set.extract(find_position());
            node.key() = new_tp;
            timer->__M_set.insert(std::move(node));
            time_point = new_tp;
        }

        template <typename Rep, typename Period>
        void update(const std::chrono::duration<Rep, Period>& dur) {
            if (dur.count() != 0) {
                update(std::chrono::system_clock::now() + dur);
            } else {
                update({});
            }
        }
    };
};
}  // namespace detail

template <typename Timer>
constexpr detail::async_operation<
    detail::tags::fxd_tmr_cncl_cntl>::fxd_tmr_cncl<Timer>*
fixed_timer_controller(Timer&, cancellation_signal& signal) noexcept(true) {
    return static_cast<detail::async_operation<
        detail::tags::fxd_tmr_cncl_cntl>::fxd_tmr_cncl<Timer>*>(signal.get());
}
template <typename Timer>
constexpr detail::async_operation<
    detail::tags::fxd_tmr_cncl_cntl>::fxd_tmr_cncl<Timer>*
safe_fixed_timer_controller(Timer&, cancellation_signal& signal) {
    return dynamic_cast<detail::async_operation<
        detail::tags::fxd_tmr_cncl_cntl>::fxd_tmr_cncl<Timer>*>(signal.get());
}
}  // namespace chx::net

namespace chx::net::detail {
template <> struct async_operation<tags::fixed_timer> {
    template <typename Timer, typename Duration, typename BindCompletionToken>
    decltype(auto) operator()(
        Timer* timer,
        const std::chrono::time_point<std::chrono::system_clock, Duration>& tp,
        BindCompletionToken&& bind_completion_token) {

        auto ite = timer->__M_set.insert(std::make_pair(
            tp, std::make_unique<io_context::task_t>(timer->__M_ctx)));
        io_context::task_t* task = ite->second.get();
        task->__M_avail = true;
        task->__M_cancel_invoke = false;
        task->__M_additional = reinterpret_cast<std::uint64_t>(timer);
        task->__M_custom_cancellation.reset(
            new async_operation<tags::fxd_tmr_cncl_cntl>::controller(timer,
                                                                     task, tp));
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) mutable {
                    assert(self);
                    token(self->__M_ec);
                    return 0;
                },
                std::forward<BindCompletionToken>(bind_completion_token))),
            std::forward<BindCompletionToken>(bind_completion_token));
    }
};
}  // namespace chx::net::detail

template <typename Timer>
template <typename Rep, typename Period, typename CompletionToken>
decltype(auto) chx::net::basic_fixed_timer<Timer>::async_register(
    const std::chrono::duration<Rep, Period>& dur,
    CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::fixed_timer>()(
        this,
        dur.count() != 0 ? (std::chrono::system_clock::now() + dur)
                         : detail::__zero_time_point,
        detail::async_token_bind<const std::error_code&>(
            std::forward<CompletionToken>(completion_token)));
}

template <typename Rep, typename Period, typename CompletionToken>
decltype(auto) chx::net::fixed_timeout_timer::async_register(
    const std::chrono::duration<Rep, Period>& dur,
    CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::fixed_timer>()(
        this,
        dur.count() != 0 ? (std::chrono::system_clock::now() + dur)
                         : detail::__zero_time_point,
        detail::async_token_bind<const std::error_code&>(
            std::forward<CompletionToken>(completion_token)));
}

template <typename Timer>
template <typename Clock, typename Duration, typename CompletionToken>
decltype(auto) chx::net::basic_fixed_timer<Timer>::async_register(
    const std::chrono::time_point<Clock, Duration>& tp,
    CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::fixed_timer>()(
        this, tp,
        detail::async_token_bind<const std::error_code&>(
            std::forward<CompletionToken>(completion_token)));
}

template <typename Clock, typename Duration, typename CompletionToken>
decltype(auto) chx::net::fixed_timeout_timer::async_register(
    const std::chrono::time_point<Clock, Duration>& tp,
    CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::fixed_timer>()(
        this, tp,
        detail::async_token_bind<const std::error_code&>(
            std::forward<CompletionToken>(completion_token)));
}
