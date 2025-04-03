#pragma once

#include "./io_context.hpp"

namespace chx::net {
class semaphore {
    template <typename Tag> friend struct detail::async_operation;
    io_context* const __M_ctx = nullptr;
    detail::interrupter __M_interrupter;

  public:
    semaphore(io_context& ctx, unsigned int init = 0)
        : __M_ctx(&ctx), __M_interrupter(init) {}

    constexpr io_context& get_associated_io_context() const noexcept(true) {
        return const_cast<io_context&>(*__M_ctx);
    }

    template <typename CompletionToken>
    decltype(auto) async_acquire(CompletionToken&& completion_token);

    void release(unsigned long c = 1) { __M_interrupter.do_interrupt(c); }

    template <typename CompletionToken>
    decltype(auto) async_acquire_shared(io_context& ctx,
                                        CompletionToken&& completion_token);
};
}  // namespace chx::net

#include "./impl/semaphore.ipp"
