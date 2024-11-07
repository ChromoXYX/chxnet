#pragma once

#include "../basic_fixed_timer.hpp"

#include "../cancellation.hpp"

namespace chx::net {
namespace detail {
namespace tags {
struct fixed_timer_controller {};
}  // namespace tags

template <> struct async_operation<tags::fixed_timer_controller> {
    template <typename Clock> struct controller;
    template <typename Clock>
    struct fixed_timer_cancellation_controller : detail::cancellation_base {
        weak_ptr<controller<Clock>> controller_;

        basic_fixed_timer<Clock>& timer() { return *controller_->timer; }
        io_context::task_t* task() { return controller_->task; }

        fixed_timer_cancellation_controller(controller<Clock>* p)
            : controller_(p->weak_from_this()) {}
        virtual ~fixed_timer_cancellation_controller() {}

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

        void update(const std::chrono::time_point<Clock>& new_tp) {
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

    template <typename Clock>
    struct controller : io_context::task_t::cancellation_controller_base,
                        enable_weak_from_this<controller<Clock>> {
        weak_ptr<basic_fixed_timer<Clock>> timer;
        io_context::task_t* const task;
        std::chrono::time_point<Clock> time_point;

        controller(basic_fixed_timer<Clock>* t, io_context::task_t* t2,
                   const std::chrono::time_point<Clock>& tp)
            : timer(t->weak_from_this()), task(t2), time_point(tp) {}

        constexpr void exclude() noexcept(true) { timer.release(); }
        constexpr bool timer_valid() noexcept(true) { return !timer.expired(); }

        virtual ~controller() {}

        void operator()(cancellation_signal& signal) override {
            if (timer_valid()) {
                signal.emplace(
                    std::make_unique<
                        fixed_timer_cancellation_controller<Clock>>(this));
            }
        }

        void cancel(io_context::task_t* t) override {
            if (timer_valid()) {
                assert(t == task);
                if (time_point != __zero_time_point<Clock>) {
                    auto ite = find_in_heap();
                    if (ite != timer->__M_heap.end()) {
                        assign_ec(task->__M_ec, errc::operation_canceled);
                        std::unique_ptr ptr = std::move(ite->second);
                        timer->__M_heap.erase(ite);
                        timer->__M_trash.push_back(std::move(ptr));
                    }
                } else {
                    auto pos = find_in_paused();
                    if (pos != timer->__M_paused.end()) {
                        assign_ec(task->__M_ec, errc::operation_canceled);
                        timer->__M_trash.emplace_back(std::move(*pos));
                        timer->__M_paused.erase(pos);
                    }
                }
                exclude();
            }
        }

        void update(const std::chrono::time_point<Clock>& new_tp) {
            if (time_point != __zero_time_point<Clock>) {
                auto ite = find_in_heap();
                assert(ite != timer->__M_heap.end());
                time_point = new_tp;
                if (new_tp != __zero_time_point<Clock>) {
                    timer->__M_heap.update(
                        ite, std::pair{new_tp, std::move(ite->second)});
                } else {
                    timer->__M_paused.emplace_back(std::move(ite->second));
                    timer->__M_heap.erase(ite);
                }
            } else {
                auto ite = find_in_paused();
                std::unique_ptr ptr = std::move(*ite);
                timer->__M_paused.erase(ite);
                time_point = new_tp;
                if (new_tp != __zero_time_point<Clock>) {
                    timer->__M_heap.emplace(new_tp, std::move(ptr));
                } else {
                    timer->__M_paused.emplace_back(std::move(ptr));
                }
            }
        }

        template <typename Rep, typename Period>
        void update(const std::chrono::duration<Rep, Period>& dur) {
            if (dur.count() != 0) {
                update(Clock::now() + dur);
            } else {
                update({});
            }
        }

      private:
        decltype(timer->__M_heap.end()) find_in_heap() noexcept(true) {
            assert(time_point != __zero_time_point<Clock>);
            return timer->__M_heap.find(
                [&](const auto& pair) { return pair.second.get() == task; });
        }
        decltype(timer->__M_paused.end()) find_in_paused() noexcept(true) {
            assert(time_point == __zero_time_point<Clock>);
            return std::find_if(
                timer->__M_paused.begin(), timer->__M_paused.end(),
                [&](const auto& ptr) { return ptr.get() == task; });
        }
    };
};
}  // namespace detail

template <typename Clock>
using fixed_timer_controller_type =
    detail::async_operation<detail::tags::fixed_timer_controller>::
        fixed_timer_cancellation_controller<Clock>;

template <typename Clock = std::chrono::steady_clock>
constexpr fixed_timer_controller_type<Clock>*
fixed_timer_controller(cancellation_signal& signal) noexcept(true) {
    return static_cast<
        detail::async_operation<detail::tags::fixed_timer_controller>::
            fixed_timer_cancellation_controller<Clock>*>(signal.get());
}
template <typename Clock = std::chrono::steady_clock>
constexpr fixed_timer_controller_type<Clock>*
safe_fixed_timer_controller(cancellation_signal& signal) {
    return dynamic_cast<
        detail::async_operation<detail::tags::fixed_timer_controller>::
            fixed_timer_cancellation_controller<Clock>*>(signal.get());
}

namespace detail {
namespace tags {
struct fixed_timer2 {};
}  // namespace tags

template <> struct async_operation<tags::fixed_timer2> {
    template <typename Clock, typename Duration, typename BindCompletionToken>
    decltype(auto)
    operator()(basic_fixed_timer<Clock>* timer,
               const std::chrono::time_point<Clock, Duration>& tp,
               BindCompletionToken&& bind_completion_token) {

        io_context::task_t* task = nullptr;
        if (tp != __zero_time_point<Clock>) {
            std::unique_ptr ptr =
                std::make_unique<io_context::task_t>(timer->__M_ctx);
            task = ptr.get();
            timer->__M_heap.emplace(tp, std::move(ptr));
        } else {
            task = timer->__M_paused
                       .emplace_back(
                           std::make_unique<io_context::task_t>(timer->__M_ctx))
                       .get();
        }
        task->__M_avail = true;
        task->__M_additional = reinterpret_cast<std::uint64_t>(timer);
        task->__M_custom_cancellation = std::make_unique<
            async_operation<tags::fixed_timer_controller>::controller<Clock>>(
            timer, task, tp);

        timer->do_loop2();

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

    template <typename Clock> void do_loop2(basic_fixed_timer<Clock>* tmr) {
        assert(!tmr->__M_is_looping);
        tmr->__M_is_looping = true;
        io_uring_prep_nop(
            tmr->get_associated_io_context().get_sqe(&tmr->__M_task));
    }
};
}  // namespace detail

template <typename Clock>
inline void chx::net::basic_fixed_timer<Clock>::do_loop2() {
    if (!__M_is_looping &&
        (!__M_heap.empty() || !__M_paused.empty() || !__M_trash.empty())) {
        detail::async_operation<detail::tags::fixed_timer2>().do_loop2(this);
    }
}

template <typename Clock>
template <typename Rep, typename Period, typename CompletionToken>
decltype(auto) chx::net::basic_fixed_timer<Clock>::async_register(
    const std::chrono::duration<Rep, Period>& dur,
    CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::fixed_timer2>()(
        this,
        dur.count() != 0 ? (Clock::now() + dur)
                         : detail::__zero_time_point<Clock>,
        detail::async_token_bind<const std::error_code&>(
            std::forward<CompletionToken>(completion_token)));
}

template <typename Clock>
template <typename Duration, typename CompletionToken>
decltype(auto) chx::net::basic_fixed_timer<Clock>::async_register(
    const std::chrono::time_point<Clock, Duration>& tp,
    CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::fixed_timer2>()(
        this, tp,
        detail::async_token_bind<const std::error_code&>(
            std::forward<CompletionToken>(completion_token)));
}
}  // namespace chx::net
