#pragma once

#include "./io_context.hpp"
#include "./ktimer.hpp"
#include "./cancellation.hpp"
#include "./timeout.hpp"
#include "./detail/flat_multimap.hpp"
#include "./detail/tracker.hpp"

#include <chrono>

namespace chx::net {
namespace detail::tags {
struct fixed_timer {};
struct fixed_timeout_timer {};
}  // namespace detail::tags

namespace detail {
constexpr std::chrono::time_point<std::chrono::system_clock> __zero_time_point;
}

template <typename Timer>
class basic_fixed_timer
    : public detail::enable_weak_from_this<basic_fixed_timer<Timer>> {
    template <typename T> friend struct detail::async_operation;

    detail::flat_multimap<std::chrono::time_point<std::chrono::system_clock>,
                          std::unique_ptr<io_context::task_t>>
        __M_set;
    std::vector<std::unique_ptr<io_context::task_t>> __M_trash;

    io_context* __M_ctx = nullptr;
    std::chrono::nanoseconds __M_interval;
    Timer __M_timer;
    bool __M_clearing = false;

    void __predestruct() noexcept(true) {
        __M_set.clear();
        __M_trash.clear();
    }

  public:
    basic_fixed_timer(io_context& ctx) : __M_ctx(&ctx), __M_timer(ctx) {}
    ~basic_fixed_timer() { __predestruct(); }

    constexpr io_context& get_associated_io_context() noexcept(true) {
        return *__M_ctx;
    }
    constexpr Timer& get_underlying_timer() noexcept(true) { return __M_timer; }
    template <typename Rep, typename Period = std::ratio<1>>
    constexpr void
    set_interval(const std::chrono::duration<Rep, Period>& dur) noexcept(true) {
        __M_interval = dur;
    }
    template <typename Rep = std::int64_t, typename Period = std::nano>
    constexpr auto get_interval() noexcept(true) {
        return std::chrono::duration_cast<std::chrono::duration<Rep, Period>>(
            __M_interval);
    }

    void listen() {
        __M_timer.expired_after(__M_interval);
        __M_timer.async_wait([this](const std::error_code& e) {
            for (auto& ptr : __M_trash) {
                ptr->__M_token(ptr.get());
            }
            __M_trash.clear();
            if (!e) {
                auto curr = std::chrono::system_clock::now();
                __M_set.consume_range(detail::__zero_time_point, curr,
                                      [](auto& v) {
                                          v.second->__M_ec.clear();
                                          v.second->__M_token(v.second.get());
                                      });
                listen();
            }
        });
    }

    template <typename Rep, typename Period, typename CompletionToken>
    decltype(auto) async_register(const std::chrono::duration<Rep, Period>& dur,
                                  CompletionToken&& completion_token);
    template <typename Clock, typename Duration, typename CompletionToken>
    decltype(auto)
    async_register(const std::chrono::time_point<Clock, Duration>& dur,
                   CompletionToken&& completion_token);

    void async_clear() {
        get_associated_io_context().async_nop(
            [this](const std::error_code& e) mutable { __M_trash.clear(); });
    }
};
using fixed_timer = basic_fixed_timer<ktimer>;

class fixed_timeout_timer
    : public detail::enable_weak_from_this<fixed_timeout_timer> {
    template <typename T> friend struct detail::async_operation;
    detail::flat_multimap<std::chrono::time_point<std::chrono::system_clock>,
                          std::unique_ptr<io_context::task_t>>
        __M_set;
    std::vector<std::unique_ptr<io_context::task_t>> __M_trash;
    io_context* __M_ctx;
    std::chrono::nanoseconds __M_interval;

    cancellation_signal __M_signal;

    void __predestruct() noexcept(true) {
        __M_set.clear();
        __M_trash.clear();
    }

  public:
    fixed_timeout_timer(io_context& ctx) : __M_ctx(&ctx) {}
    ~fixed_timeout_timer() { __predestruct(); }

    constexpr io_context& get_associated_io_context() noexcept(true) {
        return *__M_ctx;
    }
    template <typename Rep, typename Period = std::ratio<1>>
    constexpr void
    set_interval(const std::chrono::duration<Rep, Period>& dur) noexcept(true) {
        __M_interval = dur;
    }
    template <typename Rep = std::int64_t, typename Period = std::nano>
    constexpr auto get_interval() noexcept(true) {
        return std::chrono::duration_cast<std::chrono::duration<Rep, Period>>(
            __M_interval);
    }

    void listen() {
        async_timeout(
            get_associated_io_context(), __M_interval,
            bind_cancellation_signal(__M_signal, [&](const std::error_code& e) {
                for (auto& ptr : __M_trash) {
                    ptr->__M_token(ptr.get());
                }
                __M_trash.clear();
                if (!e) {
                    auto curr = std::chrono::system_clock::now();
                    __M_set.consume_range(
                        detail::__zero_time_point, curr, [](auto& v) {
                            v.second->__M_ec.clear();
                            v.second->__M_token(v.second.get());
                        });
                    listen();
                }
            }));
    }

    template <typename Rep, typename Period, typename CompletionToken>
    decltype(auto) async_register(const std::chrono::duration<Rep, Period>& dur,
                                  CompletionToken&& completion_token);
    template <typename Clock, typename Duration, typename CompletionToken>
    decltype(auto)
    async_register(const std::chrono::time_point<Clock, Duration>& dur,
                   CompletionToken&& completion_token);

    void async_clear() {
        get_associated_io_context().async_nop(
            [this](const std::error_code& e) mutable { __M_trash.clear(); });
    }

    timeout_cancellation* get_cancellation() noexcept(true) {
        return static_cast<timeout_cancellation*>(__M_signal.get());
    }
};
}  // namespace chx::net

#include "./impl/basic_fixed_timer.ipp"
