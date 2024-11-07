#pragma once

#include "./io_context.hpp"
#include "./detail/tracker.hpp"
#include <vector>

namespace chx::net {
template <typename ResourcePtr>
class semaphore : public detail::enable_weak_from_this<semaphore<ResourcePtr>> {
    template <typename Tag> friend struct detail::async_operation;
    io_context* __M_ctx = nullptr;

    std::vector<std::unique_ptr<io_context::task_t>> __M_queue, __M_trash;
    std::queue<ResourcePtr> __M_res_queue;
    bool __M_flushing = false;

  public:
    semaphore(io_context& ctx) : __M_ctx(&ctx) {}

    constexpr io_context& get_associated_io_context() const noexcept(true) {
        return const_cast<io_context&>(*__M_ctx);
    }

    template <typename CompletionToken>
    decltype(auto) async_acquire(CompletionToken&& completion_token);

    template <typename R> void release(R&& resource) {
        if (!__M_queue.empty()) {
            std::unique_ptr task = std::move(__M_queue.front());
            __M_queue.erase(__M_queue.begin());
            get_associated_io_context().async_nop(
                [task = std::move(task),
                 res = std::move(resource)](const std::error_code& e) {
                    task->__M_additional =
                        reinterpret_cast<std::uint64_t>(&res);
                    task->__M_token(task.get());
                });
        } else {
            __M_res_queue.emplace(std::forward<R>(resource));
        }
    }
};
}  // namespace chx::net

#include "./impl/semaphore.ipp"
