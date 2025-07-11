#pragma once

#include "../basic_fixed_timer.hpp"

#include "../cancellation.hpp"

namespace chx::net {
namespace detail {
namespace tags {
struct fixed_timer_controller {};
}  // namespace tags

template <> struct async_operation<tags::fixed_timer_controller> {
    template <typename Clock>
    struct controller : io_context::task_t::cancellation_controller_base {
        template <typename> friend struct async_operation;

        virtual ~controller() {}

        constexpr bool valid() noexcept(true) { return !__M_timer.expired(); }
        void cancel(io_context::task_t* t) override {
            if (valid()) {
                assert(t == __M_task);
                if (__M_tp != __zero_time_point<Clock>) {
                    auto ite = find_in_heap();
                    if (ite != __M_timer->__M_heap.end()) {
                        __M_task->__M_res = ECANCELED;
                        std::unique_ptr ptr = std::move(ite->second);
                        __M_timer->__M_heap.erase(ite);
                        __M_timer->__M_trash.push_back(std::move(ptr));
                    }
                } else {
                    auto pos = find_in_paused();
                    if (pos != __M_timer->__M_paused.end()) {
                        __M_task->__M_res = ECANCELED;
                        __M_timer->__M_trash.emplace_back(std::move(*pos));
                        __M_timer->__M_paused.erase(pos);
                    }
                }
                __M_timer->schedule();
                exclude();
            }
        }
        void update(const std::chrono::time_point<Clock>& new_tp) {
            if (__M_tp != __zero_time_point<Clock>) {
                auto ite = find_in_heap();
                assert(ite != __M_timer->__M_heap.end());
                __M_tp = new_tp;
                if (new_tp != __zero_time_point<Clock>) {
                    __M_timer->__M_heap.update(
                        ite, std::pair{new_tp, std::move(ite->second)});
                } else {
                    __M_timer->__M_paused.emplace_back(std::move(ite->second));
                    __M_timer->__M_heap.erase(ite);
                }
            } else {
                auto ite = find_in_paused();
                std::unique_ptr ptr = std::move(*ite);
                __M_timer->__M_paused.erase(ite);
                __M_tp = new_tp;
                if (new_tp != __zero_time_point<Clock>) {
                    __M_timer->__M_heap.emplace(new_tp, std::move(ptr));
                } else {
                    __M_timer->__M_paused.emplace_back(std::move(ptr));
                }
            }
            __M_timer->schedule();
        }
        template <typename Rep, typename Period>
        void update(const std::chrono::duration<Rep, Period>& dur) {
            if (dur.count() != 0) {
                update(Clock::now() + dur);
            } else {
                update({});
            }
        }
        std::chrono::time_point<Clock> time_point() const noexcept(true) {
            return __M_tp;
        }

      private:
        weak_ptr<basic_fixed_timer<Clock>> __M_timer;
        io_context::task_t* const __M_task;
        std::chrono::time_point<Clock> __M_tp;

        controller(basic_fixed_timer<Clock>* t, io_context::task_t* t2,
                   const std::chrono::time_point<Clock>& tp)
            : __M_timer(t->weak_from_this()), __M_task(t2), __M_tp(tp) {}

        constexpr void exclude() noexcept(true) { __M_timer.release(); }

        decltype(__M_timer->__M_heap.end()) find_in_heap() noexcept(true) {
            assert(__M_tp != __zero_time_point<Clock>);
            return __M_timer->__M_heap.find([&](const auto& pair) {
                return pair.second.get() == __M_task;
            });
        }
        decltype(__M_timer->__M_paused.end()) find_in_paused() noexcept(true) {
            assert(__M_tp == __zero_time_point<Clock>);
            return std::find_if(
                __M_timer->__M_paused.begin(), __M_timer->__M_paused.end(),
                [&](const auto& ptr) { return ptr.get() == __M_task; });
        }
    };
};
}  // namespace detail

template <typename Clock>
using fixed_timer_controller_type = detail::async_operation<
    detail::tags::fixed_timer_controller>::controller<Clock>;

template <typename Clock = std::chrono::steady_clock>
constexpr fixed_timer_controller_type<Clock>*
fixed_timer_controller(cancellation_signal& signal) noexcept(true) {
    return static_cast<detail::async_operation<
        detail::tags::fixed_timer_controller>::controller<Clock>*>(
        detail::async_operation<detail::tags::cancellation_get_task>()(signal)
            ->__M_custom_cancellation.get());
}
template <typename Clock = std::chrono::steady_clock>
constexpr fixed_timer_controller_type<Clock>*
safe_fixed_timer_controller(cancellation_signal& signal) {
    return dynamic_cast<detail::async_operation<
        detail::tags::fixed_timer_controller>::controller<Clock>*>(
        detail::async_operation<detail::tags::cancellation_get_task>()(signal)
            ->__M_custom_cancellation.get());
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
        task->__M_additional_val = reinterpret_cast<std::uint64_t>(timer);
        task->__M_custom_cancellation.reset(
            new async_operation<tags::fixed_timer_controller>::controller<
                Clock>(timer, task, tp));

        timer->schedule();

        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) mutable {
                    assert(self);
                    token(self->__M_res == 0 ? std::error_code{}
                                             : make_ec(self->__M_res));
                    return 0;
                },
                bind_completion_token)),
            bind_completion_token);
    }

    template <typename Clock> void do_poll(basic_fixed_timer<Clock>* tmr) {
        if (!tmr->__M_is_polling) {
            io_uring_prep_nop(
                tmr->get_associated_io_context().get_sqe(&tmr->__M_poll_task));
            tmr->__M_is_polling = true;
        }
    }
    template <typename Clock>
    void do_ktimer_poll(basic_fixed_timer<Clock>* tmr) {
        if (!tmr->__M_is_ktimer_polling) {
            tmr->__M_ktimer.expired_after(tmr->__M_res);
            io_uring_sqe* sqe =
                tmr->get_associated_io_context().get_sqe(&tmr->__M_timer_task);
            io_uring_prep_read(sqe, tmr->__M_ktimer.native_handler(),
                               &tmr->__M_timer_task.__M_additional_val, 8, 0);
            tmr->__M_is_ktimer_polling = true;
        }
    }
};
}  // namespace detail

template <typename Clock>
inline void chx::net::basic_fixed_timer<Clock>::schedule() {
    if (__M_is_polling) {
        return;
    }
    if (!__M_trash.empty()) {
        return detail::async_operation<detail::tags::fixed_timer2>().do_poll(
            this);
    }
    if (!__M_heap.empty()) {
        const std::chrono::time_point<Clock>& first = __M_heap.begin()->first;
        if (!__M_is_ktimer_polling) {
            if (Clock::now() + __M_res > first) {
                detail::async_operation<detail::tags::fixed_timer2>().do_poll(
                    this);
            } else {
                detail::async_operation<detail::tags::fixed_timer2>()
                    .do_ktimer_poll(this);
            }
        } else if (Clock::now() + __M_ktimer.expired_after() > first) {
            detail::async_operation<detail::tags::fixed_timer2>().do_poll(this);
        }
    }
}

template <typename Clock>
inline void chx::net::basic_fixed_timer<Clock>::callback() {
    auto trash = std::move(__M_trash);
    for (auto& ptr : trash) {
        ptr->__M_token(ptr.get());
    }
    const auto curr = Clock::now();
    while (!__M_heap.empty() && __M_heap.top().first <= curr) {
        std::unique_ptr ptr = std::move(__M_heap.top().second);
        __M_heap.pop();
        ptr->__M_res = 0;
        ptr->__M_token(ptr.get());
    }
    schedule();
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
