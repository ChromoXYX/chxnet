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
        controller<Timer>* controller_ = nullptr;

        Timer* timer() { return controller_->timer; }
        io_context::task_t* task() { return controller_->task; }

        fxd_tmr_cncl(controller<Timer>* p) : controller_(p) {}
        ~fxd_tmr_cncl() { release(); }

        void release() {
            if (valid()) {
                for (auto ite = controller_->tracker().lower_bound(task());
                     ite != controller_->tracker().end() &&
                     ite->first == task();
                     ++ite) {
                    if (ite->second == this) {
                        controller_->tracker().erase(ite);
                        break;
                    }
                }
                controller_ = nullptr;
            }
        }
        constexpr bool valid() noexcept(true) { return controller_ != nullptr; }

        void operator()() override {
            if (valid()) {
                if (auto ite = find_position(); ite != timer()->__M_set.end()) {
                    assign_ec(task()->__M_ec, errc::operation_canceled);
                    // task()->__M_token(task());
                    // timer()->__M_set.erase(ite);
                    timer()->__M_trash.emplace_back(
                        std::move(timer()->__M_set.extract(ite).mapped()));
                    release();
                }
            }
        }

        auto find_position() noexcept(true) {
            auto [begin, end] =
                timer()->__M_set.equal_range(controller_->time_point);
            for (auto ite = begin; ite != end; ++ite) {
                if (ite->second.get() == task()) {
                    return ite;
                }
            }
            return timer()->__M_set.end();
        }

        void update(
            const std::chrono::time_point<std::chrono::system_clock>& new_tp) {
            try {
                auto node = timer()->__M_set.extract(find_position());
                node.key() = new_tp;
                timer()->__M_set.insert(std::move(node));
                controller_->time_point = new_tp;
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

    template <typename Timer> struct controller : custom_cancellation_base {
        Timer* const timer;
        io_context::task_t* const task;
        std::chrono::time_point<std::chrono::system_clock> time_point;

        controller(Timer* t, io_context::task_t* t2,
                   const std::chrono::time_point<std::chrono::system_clock>& tp)
            : timer(t), task(t2), time_point(tp) {}

        constexpr auto& tracker() noexcept(true) { return timer->__M_tracker; }

        ~controller() {
            for (auto ite = tracker().lower_bound(task);
                 ite != tracker().end() && ite->first == task; ++ite) {
                static_cast<fxd_tmr_cncl<Timer>*>(ite->second)->controller_ =
                    nullptr;
            }
            tracker().erase(task);
        }

        void operator()(cancellation_signal& signal) override {
            auto* p = new fxd_tmr_cncl<Timer>(this);
            tracker().emplace(task, p);
            signal.emplace(p);
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
        task->__M_cancel_invoke = true;
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
