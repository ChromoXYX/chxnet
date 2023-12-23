#pragma once

#include "./io_context.hpp"

#include <chrono>

namespace chx::net {
template <typename Rep, typename Period, typename CompletionToken>
decltype(auto) async_timeout(io_context& ctx,
                             const std::chrono::duration<Rep, Period>& dur,
                             CompletionToken&& completion_token);

class timeout_handler {
    template <typename Tag> friend struct detail::async_operation;
    io_context* ctx;
    io_context::task_t* self;

  public:
    template <typename Rep, typename Period, typename CompletionToken>
    decltype(auto) async_update(const std::chrono::duration<Rep, Period>& dur,
                                CompletionToken&& completion_token);
    template <typename CompletionToken>
    decltype(auto) async_remove(CompletionToken&& completion_token);
};

template <typename CompletionToken>
decltype(auto) bind_timeout_handler(timeout_handler& h,
                                    CompletionToken&& completion_token);
}  // namespace chx::net

#include "./impl/timeout.ipp"
