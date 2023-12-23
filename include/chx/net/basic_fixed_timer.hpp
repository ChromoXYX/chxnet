#pragma once

#include "./io_context.hpp"
#include "./ktimer.hpp"
#include "./cancellation.hpp"
#include "./timeout.hpp"

#include <chrono>
#include <map>

namespace chx::net {
namespace detail::tags {
struct fixed_timer {};
struct fixed_timeout_timer {};
}  // namespace detail::tags

template <typename Timer> class basic_fixed_timer : CHXNET_NONCOPYABLE {
    friend struct detail::async_operation<detail::tags::fixed_timer>;

    io_context* __M_ctx = nullptr;
    std::chrono::nanoseconds __M_interval;
    Timer __M_timer;

    std::multimap<std::chrono::time_point<std::chrono::system_clock>,
                  std::unique_ptr<io_context::task_t>>
        __M_set;

  public:
    basic_fixed_timer(io_context& ctx) : __M_ctx(&ctx), __M_timer(ctx) {}
    basic_fixed_timer(Timer&& timer)
        : __M_ctx(&timer.get_associated_io_context()),
          __M_timer(std::move(timer)) {}

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
        });
    }

    template <typename Rep, typename Period, typename CompletionToken>
    decltype(auto) async_register(const std::chrono::duration<Rep, Period>& dur,
                                  CompletionToken&& completion_token);

    template <typename CompletionToken>
    decltype(auto) bind_cancellation_signal(cancellation_signal& signal,
                                            CompletionToken&& completion_token);
};
using fixed_timer = basic_fixed_timer<ktimer>;

class fixed_timeout_timer : CHXNET_NONCOPYABLE {
    friend struct detail::async_operation<detail::tags::fixed_timeout_timer>;
    io_context* __M_ctx;
    std::multimap<std::chrono::time_point<std::chrono::system_clock>,
                  std::unique_ptr<io_context::task_t>>
        __M_set;
    std::chrono::nanoseconds __M_interval;

    timeout_handler __M_handler;

  public:
    fixed_timeout_timer(io_context& ctx) : __M_ctx(&ctx) {
        detail::async_operation<detail::tags::io_uring_timeout>()
            .set_io_context(__M_ctx, __M_handler);
    }

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
        if (__M_interval.count() != 0)
            async_timeout(
                get_associated_io_context(), __M_interval,
                bind_timeout_handler(
                    get_timeout_handler(), [&](const std::error_code& e) {
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
                            __M_set.erase(__M_set.begin(),
                                          __M_set.lower_bound(curr));
                            listen();
                        }
                    }));
    }

    template <typename Rep, typename Period, typename CompletionToken>
    decltype(auto) async_register(const std::chrono::duration<Rep, Period>& dur,
                                  CompletionToken&& completion_token);
    template <typename CompletionToken>
    decltype(auto) bind_cancellation_signal(cancellation_signal& signal,
                                            CompletionToken&& completion_token);

    constexpr timeout_handler& get_timeout_handler() noexcept(true) {
        return __M_handler;
    }
};
}  // namespace chx::net

#include "./impl/basic_fixed_timer.ipp"
