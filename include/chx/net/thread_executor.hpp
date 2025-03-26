#pragma once

#include "./detail/noncopyable.hpp"
#include <thread>
#include <condition_variable>
#include <queue>

namespace chx::net {
class thread_executor {
    CHXNET_NONCOPYABLE;
    CHXNET_NONMOVEABLE;

    std::thread __M_th;

    alignas(64) std::mutex __M_m;
    std::condition_variable __M_cv;

    struct message_base {
        virtual ~message_base() = default;
        virtual int operator()(thread_executor*) = 0;
    };
    std::queue<std::unique_ptr<message_base>> __M_q;
    bool __M_stop = false;

    void worker() {
        for (;;) {
            std::queue<std::unique_ptr<message_base>> c, r;
            {
                std::unique_lock ul(__M_m);
                __M_cv.wait(ul, [&]() { return !__M_q.empty() || __M_stop; });
                c = std::move(__M_q);
            }

            while (!c.empty() && !__M_stop) {
                auto ptr = std::move(c.front());
                c.pop();
                if ((*ptr)(this)) {
                    r.push(std::move(ptr));
                }
            }
            if (__M_stop) {
                return;
            }
            if (!r.empty()) {
                std::lock_guard lg(__M_m);
                while (!r.empty()) {
                    __M_q.push(std::move(r.front()));
                    r.pop();
                }
            }
        }
    }

  public:
    thread_executor() { __M_th = std::thread(&thread_executor::worker, this); }

    template <typename Fn> void post(Fn&& fn) {
        using __decay_t = std::decay_t<Fn>;
        struct impl : message_base, __decay_t {
            impl(Fn&& fn) : __decay_t(std::forward<Fn>(fn)) {}

            int operator()(thread_executor* ctx) override {
                if constexpr (std::is_invocable_v<__decay_t,
                                                  thread_executor*>) {
                    if constexpr (!std::is_same_v<
                                      std::invoke_result_t<__decay_t,
                                                           thread_executor*>,
                                      void>) {
                        return __decay_t::operator()(ctx);
                    } else {
                        return __decay_t::operator()(ctx), 0;
                    }
                } else {
                    if constexpr (!std::is_same_v<
                                      std::invoke_result_t<__decay_t>, void>) {
                        return __decay_t::operator()();
                    } else {
                        return __decay_t::operator()(), 0;
                    }
                }
            }
        };
        std::unique_ptr<message_base> msg =
            std::make_unique<impl>(std::forward<Fn>(fn));
        std::lock_guard lg(__M_m);
        __M_q.emplace(std::move(msg));
    }
    void interrupt() { __M_cv.notify_all(); }
    void stop() { __M_stop = true; }
    void join() { __M_th.join(); }
};
}  // namespace chx::net
