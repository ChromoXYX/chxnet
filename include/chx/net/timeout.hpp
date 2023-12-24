#pragma once

#include "./io_context.hpp"
#include "./cancellation.hpp"

#include <chrono>

namespace chx::net {
template <typename Rep, typename Period, typename CompletionToken>
decltype(auto) async_timeout(io_context& ctx,
                             const std::chrono::duration<Rep, Period>& dur,
                             CompletionToken&& completion_token);

class timeout_cancellation : public detail::cancellation_base {
    template <typename Tag> friend struct detail::async_operation;
    // io_context* ctx = nullptr;
    io_context::task_t* self = nullptr;

  public:
    timeout_cancellation(io_context::task_t* t) noexcept(true) : self(t) {}

    void operator()() override {
        detail::async_operation<detail::tags::outer_cancel>().normal_cancel(
            &self->get_associated_io_context(), self);
    }

    template <typename Rep, typename Period, typename CompletionToken>
    decltype(auto) async_update(const std::chrono::duration<Rep, Period>& dur,
                                CompletionToken&& completion_token);
    template <typename CompletionToken>
    decltype(auto) async_remove(CompletionToken&& completion_token);
};
}  // namespace chx::net

#include "./impl/timeout.ipp"
