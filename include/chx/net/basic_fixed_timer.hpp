#pragma once

#include "./io_context.hpp"
#include "./detail/dary_heap.hpp"
#include "./detail/tracker.hpp"
#include "./ktimer.hpp"

#include <chrono>

namespace chx::net {
namespace detail {
template <typename Clock>
constexpr std::chrono::time_point<Clock> __zero_time_point = {};
}

template <typename Clock>
class basic_fixed_timer
    : public detail::enable_weak_from_this<basic_fixed_timer<Clock>> {
    template <typename T> friend struct detail::async_operation;

    detail::dary_heap<4, std::chrono::time_point<Clock>,
                      std::unique_ptr<io_context::task_t>>
        __M_heap;
    std::vector<std::unique_ptr<io_context::task_t>> __M_paused;
    std::vector<std::unique_ptr<io_context::task_t>> __M_trash;

    io_context::task_t __M_timer_task;
    io_context::task_t __M_poll_task;

    io_context* __M_ctx = nullptr;
    const std::chrono::nanoseconds __M_res;

    ktimer __M_ktimer;

    bool __M_is_polling = false;
    bool __M_is_ktimer_polling = false;

    void schedule();
    void callback();

  public:
    basic_fixed_timer(io_context& ctx)
        : __M_ctx(&ctx), __M_timer_task(&ctx), __M_poll_task(&ctx),
          __M_ktimer(ctx), __M_res(std::chrono::milliseconds(500)) {
        __M_poll_task.__M_persist = true;
        __M_poll_task.__M_token.emplace([this](io_context::task_t*) {
            __M_is_polling = false;
            callback();
            return 0;
        });

        __M_timer_task.__M_persist = true;
        __M_timer_task.__M_token.emplace([this](io_context::task_t*) {
            __M_is_ktimer_polling = false;
            callback();
            return 0;
        });
    }

    constexpr io_context& get_associated_io_context() noexcept(true) {
        return *__M_ctx;
    }

    template <typename Rep, typename Period, typename CompletionToken>
    decltype(auto) async_register(const std::chrono::duration<Rep, Period>& dur,
                                  CompletionToken&& completion_token);
    template <typename Duration, typename CompletionToken>
    decltype(auto)
    async_register(const std::chrono::time_point<Clock, Duration>& dur,
                   CompletionToken&& completion_token);
};

using fixed_timer = basic_fixed_timer<std::chrono::steady_clock>;
}  // namespace chx::net

#include "./impl/basic_fixed_timer.ipp"
