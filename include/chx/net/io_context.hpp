#pragma once

#include <cassert>
#include <liburing.h>
#include <sys/eventfd.h>

#include <memory>
#include <queue>
#include <algorithm>
#include <mutex>

#include "./task_decl.hpp"
#include "./detail/basic_token_storage.hpp"
#include "./detail/noncopyable.hpp"
#include "./detail/interrupter.hpp"
#include "./detail/scope_exit.hpp"
#include "./detail/task_decl_ring_buffer.hpp"
#include "./error_code.hpp"
#include "./exception.hpp"

namespace chx::net {
class io_context;
struct cancellation_signal;

namespace detail {
template <typename Tag> struct async_operation;
namespace tags {
struct use_delivery {};
struct interrupter {};
}  // namespace tags
}  // namespace detail

class io_context {
    CHXNET_NONCOPYABLE
    CHXNET_NONMOVEABLE

    template <typename Tag> friend struct detail::async_operation;

  public:
    /**
     * @brief Type which carries necessary data for a single async task.
     *
     */
    using task_t = task_decl;

  protected:
    struct message_base {
        virtual ~message_base() = default;
        virtual int operator()(io_context*) = 0;
    };

    io_uring __M_ring;
    bool __M_stopped = false;
    const std::size_t __M_ring_sz;

    task_decl __M_outstanding_task_list;
    std::size_t __M_outstanding_task_list_n = 0;
    detail::task_decl_ring_buffer<256> __M_task_pool;

    std::queue<io_uring_sqe> __M_sqe_backlog;
    void flush_sqe_backlog() {
        while (!__M_sqe_backlog.empty() &&
               !io_uring_cq_has_overflow(&__M_ring)) {
            io_uring_sqe* sqe = io_uring_get_sqe(&__M_ring);
            if (!sqe) {
                int r = io_uring_submit(&__M_ring);
                if (r < 0) {
                    if (r == -EBUSY) {
                        return;
                    } else {
                        __CHXNET_THROW_EC(make_ec(-r));
                    }
                }
                sqe = io_uring_get_sqe(&__M_ring);
                if (!sqe) {
                    return;
                }
            }
            *sqe = __M_sqe_backlog.front();
            __M_sqe_backlog.pop();
        }
    }

    constexpr void task_list_insert(task_decl* task) noexcept(true) {
        assert(!task->__M_next && !task->__M_prev);
        if (__M_outstanding_task_list.__M_next) {
            __M_outstanding_task_list.__M_next->__M_prev = task;
        }
        task->__M_next = __M_outstanding_task_list.__M_next;
        task->__M_prev = &__M_outstanding_task_list;
        __M_outstanding_task_list.__M_next = task;
        ++__M_outstanding_task_list_n;
    }
    void task_list_erase(task_decl* task) {
        --__M_outstanding_task_list_n;
        if (task->__M_prev) {
            task->__M_prev->__M_next = task->__M_next;
        }
        if (task->__M_next) {
            task->__M_next->__M_prev = task->__M_prev;
        }
        task->__M_prev = task->__M_next = nullptr;
        __M_task_pool.push(std::unique_ptr<task_decl>(task));
    }

    alignas(64) std::mutex __M_msg_list_mutex;
    alignas(64) std::atomic_bool __M_msg_list_empty = true;
    std::vector<std::unique_ptr<message_base>> __M_msg_list;

    static_assert(
        std::is_nothrow_destructible_v<task_t> &&
        std::is_nothrow_destructible_v<decltype(__M_outstanding_task_list)>);

    detail::interrupter __M_interrupter;
    detail::interrupter __M_blocker;
    bool __M_blocked = false;

    struct {
    } __M_msg_interrupt_data;
    static_assert(sizeof(__M_msg_interrupt_data));

  protected:
    task_t* acquire() {
        try {
            task_t* r = __M_task_pool.pop() ?: new task_t(this);
            return task_list_insert(r), r;
        } catch (const std::exception&) {
            rethrow_with_fatal(std::make_exception_ptr(
                __CHXNET_MAKE_EX_CSTR("failed to obtain a task_t")));
        }
    }

    void release(task_t* task) {
        try {
            assert(task);
            task->reset();
            task_list_erase(task);
        } catch (const std::exception&) {
            rethrow_with_fatal(std::current_exception());
        }
    }

    [[nodiscard]] io_uring_sqe* get_sqe(task_t* task = nullptr) {
        auto* sqe = io_uring_get_sqe(&__M_ring);
        if (sqe) {
            io_uring_sqe_set_data(sqe, task);
            return sqe;
        } else {
            int r = io_uring_submit(&__M_ring);
            if (r >= 0) {
                sqe = io_uring_get_sqe(&__M_ring);
                if (!sqe) {
                    rethrow_with_fatal(std::make_exception_ptr(
                        __CHXNET_MAKE_EX_CSTR("Cannot obtain io_uring_sqe*")));
                }
            } else if (r == -EBUSY) {
                return &__M_sqe_backlog.emplace();
            } else {
                rethrow_with_fatal(
                    std::make_exception_ptr(__CHXNET_MAKE_EX_CODE(-r)));
            }
            io_uring_sqe_set_data(sqe, task);
            return sqe;
        }
    }

    [[nodiscard]] std::pair<io_uring_sqe*, task_t*> get() {
        std::pair<io_uring_sqe*, task_t*> _r{get_sqe(), acquire()};
        io_uring_sqe_set_data(_r.first, _r.second);
        return _r;
    }
    void get(io_uring_sqe** sqe, task_t** task) {
        *sqe = get_sqe();
        *task = acquire();
        io_uring_sqe_set_data(*sqe, *task);
    }
    void cancel_task(task_t* task, int flags = 0) {
        auto* sqe = get_sqe();
        io_uring_prep_cancel(sqe, task, flags);
        sqe->flags = IOSQE_CQE_SKIP_SUCCESS;
    }

    template <typename... Signature, typename FinalFunctor,
              typename CompletionToken>
    decltype(auto) async_delivery(FinalFunctor&& final_functor,
                                  CompletionToken&& completion_token);

  private:
    void __handle_task(io_uring_cqe* cqe) {
        task_t* task = static_cast<task_t*>(io_uring_cqe_get_data(cqe));
        task->__M_cqe = cqe;
        if (!task->__M_notif && !task->__M_persist) {
            try {
                task->__M_token(task);
            } catch (const std::exception&) {
                release(task);
                std::rethrow_exception(std::current_exception());
            }
            release(task);
        } else {
            detail::scope_exit _(
                [this,
                 more = task->__M_persist || (cqe->flags & IORING_CQE_F_MORE),
                 task]() {
                    if (!more) {
                        release(task);
                    }
                });
            task->__M_token(task);
        }
    }
    void __handle_msg() {
        if (!__M_msg_list_empty.load(std::memory_order_relaxed)) {
            std::vector<std::unique_ptr<message_base>> v;
            {
                std::lock_guard lg(__M_msg_list_mutex);
                v = std::move(__M_msg_list);
                __M_msg_list_empty.store(true, std::memory_order_relaxed);
            }
            std::size_t i = 0;
            std::vector<std::unique_ptr<message_base>> next;
            try {
                for (; i < v.size(); ++i) {
                    if (!(*v[i])(this)) {
                        v[i].reset();
                    } else {
                        try {
                            next.emplace_back(std::move(v[i]));
                        } catch (const std::exception&) {
                            rethrow_with_fatal(std::current_exception());
                        }
                    }
                }
                try {
                    if (!next.empty()) {
                        {
                            std::lock_guard lg(__M_msg_list_mutex);
                            __M_msg_list.insert(
                                __M_msg_list.end(),
                                std::make_move_iterator(next.begin()),
                                std::make_move_iterator(next.end()));
                            next.clear();
                            __M_msg_list_empty.store(false,
                                                     std::memory_order_relaxed);
                        }
                        interrupt();
                    }
                } catch (const std::exception&) {
                    rethrow_with_fatal(std::current_exception());
                }
            } catch (const std::exception& ex) {
                try {
                    if (i + 1 < v.size()) {
                        std::lock_guard lg(__M_msg_list_mutex);
                        __M_msg_list.insert(
                            __M_msg_list.end(),
                            std::make_move_iterator(v.begin() + i + 1),
                            std::make_move_iterator(v.end()));
                        __M_msg_list_empty.store(false,
                                                 std::memory_order_relaxed);
                    }
                    if (!next.empty()) {
                        {
                            std::lock_guard lg(__M_msg_list_mutex);
                            __M_msg_list.insert(
                                __M_msg_list.end(),
                                std::make_move_iterator(next.begin()),
                                std::make_move_iterator(next.end()));
                            next.clear();
                            __M_msg_list_empty.store(false,
                                                     std::memory_order_relaxed);
                        }
                        interrupt();
                    }
                } catch (const std::exception&) {
                    rethrow_with_fatal(std::current_exception());
                }
                std::rethrow_exception(std::current_exception());
            }
        }
    }

    void __run() {
        while (outstanding_tasks() || __M_blocked) {
            if (io_uring_submit_and_wait(&__M_ring, 1) >= 0) {
                flush_sqe_backlog();
            }

            io_uring_cqe* cqe;
            unsigned head;
            struct nr_guard {
                unsigned nr = 0;
                io_uring* const ring = nullptr;

                constexpr nr_guard(io_uring* r) noexcept(true) : ring(r) {}
                ~nr_guard() noexcept(true) { io_uring_cq_advance(ring, nr); }

                constexpr void operator++() noexcept(true) { ++nr; }
            } nr(&__M_ring);
            io_uring_for_each_cqe(&__M_ring, head, cqe) {
                ++nr;
                if (cqe->user_data) {
                    void* data = io_uring_cqe_get_data(cqe);
                    if (data == static_cast<void*>(&__M_interrupter)) {
                        if (cqe->res > 0) {
                            __M_interrupter.do_read(get_sqe(),
                                                    &__M_interrupter);
                            __handle_msg();
                        } else {
                            rethrow_with_fatal(
                                std::make_exception_ptr(strerror(-cqe->res)));
                        }
                    } else if (data == static_cast<void*>(&__M_blocker)) {
                        if (cqe->res > 0) {
                            __M_blocked = false;
                        } else {
                            rethrow_with_fatal(
                                std::make_exception_ptr(strerror(-cqe->res)));
                        }
                    } else {
                        __handle_task(cqe);
                    }
                }
                if (is_stopped()) {
                    return;
                }
            }
        }
    }

    void __async_cancel_all() {
        task_decl* node = __M_outstanding_task_list.__M_next;
        while (node) {
            auto* sqe = get_sqe();
            io_uring_prep_cancel(sqe, node, IORING_ASYNC_CANCEL_ALL);
            node = node->__M_next;
        }
    }

    [[deprecated]] void submit() {
        if (int r = io_uring_submit(&__M_ring); r >= 0) {
            return;
        } else {
            rethrow_with_fatal(std::make_exception_ptr(
                __CHXNET_MAKE_EX_CSTR("io_uring_submit failed")));
        }
    }

  public:
    io_context(struct io_uring_params params = {},
               std::size_t static_task_sz = 4096)
        : __M_ring_sz(static_task_sz > 4096 ? static_task_sz : 4096),
          __M_outstanding_task_list(this) {
        params.flags |= IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;
        if (int r = io_uring_queue_init_params(__M_ring_sz, &__M_ring, &params);
            r != 0) {
            rethrow_with_fatal(
                std::make_exception_ptr(__CHXNET_MAKE_EX_CODE(-r)));
        }
        __M_interrupter.do_read(get_sqe(), &__M_interrupter);
    }

    /**
     * @brief Destroy the io_context object.
     *
     */
    ~io_context() {
        io_uring_queue_exit(&__M_ring);
        task_decl* node = __M_outstanding_task_list.__M_next;
        while (node) {
            if (node->__M_prev) {
                node->__M_prev->__M_next = node->__M_next;
            }
            if (node->__M_next) {
                node->__M_next->__M_prev = node->__M_prev;
            }
            delete std::exchange(node, node->__M_next);
        }
    }
    /**
     * @brief Start waiting for async tasks to be completed.
     *
     * @note Calling this function at any stage during the processing of an
     * async task is undefined behavior.
     *
     */
    void run() {
        if (!is_stopped()) {
            __run();
        }
    }

    void block() {
        if (!__M_blocked) {
            __M_blocker.do_read(get_sqe(), &__M_blocker);
            __M_blocked = true;
        }
    }
    void unblock() { __M_blocker.do_interrupt(); }

    /**
     * @brief Stop handling the completion of async tasks;
     *
     */
    constexpr void stop() noexcept(true) { __M_stopped = true; }
    /**
     * @brief Determine whether the io_context is stopped.
     *
     * @return true The io_context is stopped.
     * @return false The io_context is not stopped.
     */
    constexpr bool is_stopped() noexcept(true) { return __M_stopped; }
    /**
     * @brief Restart handling the completion of async tasks.
     *
     */
    constexpr void restart() noexcept(true) { __M_stopped = false; }

    /**
     * @brief Submit a no-operation async task.
     *
     * @tparam CompletionToken Callable object with signature
     * \code
     * void(const std::error_code&)
     * \endcode
     * @param completion_token Completion token which will be invoked when the
     * async task is completed.
     * @return decltype(auto)
     */
    template <typename CompletionToken>
    decltype(auto) async_nop(CompletionToken&& completion_token);

    template <typename Fn> void post(Fn&& fn) {
        using __decay_t = std::decay_t<Fn>;
        struct impl : message_base, __decay_t {
            impl(Fn&& fn) : __decay_t(std::forward<Fn>(fn)) {}

            int operator()(io_context* ctx) override {
                if constexpr (std::is_invocable_v<__decay_t, io_context*>) {
                    if constexpr (!std::is_same_v<std::invoke_result_t<
                                                      __decay_t, io_context*>,
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
        std::lock_guard lg(__M_msg_list_mutex);
        __M_msg_list.emplace_back(std::move(msg));
        __M_msg_list_empty.store(false, std::memory_order_relaxed);
    }
    void interrupt() const noexcept(true) { __M_interrupter.do_interrupt(); }

    constexpr std::size_t outstanding_tasks() const noexcept(true) {
        return __M_outstanding_task_list_n;
    }
    constexpr int native_handler() const noexcept(true) {
        return __M_ring.ring_fd;
    }
};
}  // namespace chx::net

template <>
struct chx::net::detail::async_operation<chx::net::detail::tags::use_delivery> {
    template <typename... Signature, typename FinalFunctor,
              typename CompletionToken>
    decltype(auto) oper(io_context* ctx, FinalFunctor&& final_functor,
                        CompletionToken&& completion_token) {
        return ctx->async_delivery<Signature...>(
            std::forward<FinalFunctor>(final_functor),
            std::forward<CompletionToken>(completion_token));
    }
};

#include "./impl/io_context.ipp"
