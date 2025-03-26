#pragma once

#include "./io_context.hpp"
#include <condition_variable>

namespace chx::net {
class channel {
    CHXNET_NONCOPYABLE;
    CHXNET_NONMOVEABLE;

    io_context& __M_self;
    // io_uring __M_ring;

    alignas(64) std::mutex __M_m;
    std::condition_variable __M_cv;
    std::queue<task_decl*> __M_backlog;

  public:
    channel(io_context& ctx) : __M_self(ctx) {}

    void post(task_decl* task) {
        {
            std::lock_guard lg(__M_m);
            __M_backlog.push(task);
        }
        interrupt();
    }
    void interrupt() noexcept(true) { __M_cv.notify_all(); }

    [[nodiscard]] task_decl* acquire() {
        std::unique_lock ul(__M_m);
        __M_cv.wait(ul, [this]() { return !__M_backlog.empty(); });
        task_decl* r = __M_backlog.front();
        __M_backlog.pop();
        return r;
    }
    constexpr io_context& get_associated_io_context() noexcept(true) {
        return __M_self;
    }
};
}  // namespace chx::net
