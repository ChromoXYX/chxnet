#pragma once

#include "./io_context.hpp"
#include "./detail/dary_heap.hpp"
#include "./detail/tracker.hpp"

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

    io_context::task_t __M_task;

    io_context* __M_ctx = nullptr;
    bool __M_is_looping = false;

    void do_loop2();

    void do_flush() {
        __M_is_looping = false;
        auto trash = std::move(__M_trash);
        for (auto& ptr : trash) {
            ptr->__M_token(ptr.get());
            ptr.reset();
        }
        auto curr = Clock::now();
        while (!__M_heap.empty() && __M_heap.top().first <= curr) {
            std::unique_ptr ptr = std::move(__M_heap.top().second);
            __M_heap.pop();
            ptr->__M_res = 0;
            ptr->__M_token(ptr.get());
        }
        do_loop2();
    }

  public:
    basic_fixed_timer(io_context& ctx) : __M_ctx(&ctx), __M_task(&ctx) {
        __M_task.__M_persist = true;
        __M_task.__M_token.emplace([this](io_context::task_t*) {
            do_flush();
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
