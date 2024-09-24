#pragma once

#include <cassert>
#include <liburing.h>

#include <memory>
#include <queue>
#include <list>

#include "./detail/task_declare.hpp"
#include "./detail/basic_token_storage.hpp"
#include "./detail/noncopyable.hpp"
#include "./error_code.hpp"
#include "./exception.hpp"

#include <cstdint>

#ifndef CHXNET_TOKEN_STORAGE_SIZE
#define CHXNET_TOKEN_STORAGE_SIZE 48
#endif

#ifndef CHXNET_ENABLE_SQPOLL
#define CHXNET_ENABLE_SQPOLL 0
#endif

namespace chx::net {
class io_context;

struct cancellation_signal;

namespace detail {
template <typename Tag> struct async_operation;
namespace tags {
struct use_delivery {};
}  // namespace tags

struct task_declare::task_decl : CHXNET_NONCOPYABLE {
    struct cancellation_controller_base {
        virtual void operator()(cancellation_signal&) = 0;
        virtual void cancel(task_decl*) = 0;
        virtual ~cancellation_controller_base() = default;
    };

    task_decl(io_context* p) noexcept(true) : __M_ctx(p) {}

    io_context* __M_ctx = nullptr;

    std::uint64_t __M_additional = {};

    bool __M_avail = true;
    bool __M_persist = false;
    bool __M_notif = false;
    bool __M_cancel_invoke = false;
    bool __M_option5 = false;
    bool __M_option6 = false;
    bool __M_option7 = false;
    // std::size_t __M_dyn_idx = 0;
    // constexpr static std::size_t __END = -1;
    std::list<std::unique_ptr<task_decl>>::iterator __M_location;
    static_assert(sizeof(__M_location) == sizeof(std::size_t));

    std::error_code __M_ec;
    int __M_res;

    std::unique_ptr<cancellation_controller_base> __M_custom_cancellation;

    detail::basic_token_storage<int(task_decl*), CHXNET_TOKEN_STORAGE_SIZE>
        __M_token;

    void reset() noexcept(true) {
        __M_ec.clear();
        __M_res = 0;
        __M_persist = false;
        __M_notif = false;
        __M_cancel_invoke = false;

        __M_custom_cancellation.reset();
    }

    constexpr io_context& get_associated_io_context() noexcept(true) {
        return *__M_ctx;
    }
    void* get_underlying_data() noexcept(true) {
        return __M_token.underlying_data();
    }
};
}  // namespace detail

class io_context : CHXNET_NONCOPYABLE {
    template <typename Tag> friend struct detail::async_operation;

  public:
    /**
     * @brief Type which carries necessary data for a single async task.
     *
     */
    using task_t = detail::task_declare::task_decl;

  protected:
    io_uring __M_ring;
    bool __M_stopped = false;
    // bool __M_destructing = false;

    // std::vector<std::unique_ptr<task_t>> __M_dynamic_task_queue;
    std::queue<std::unique_ptr<task_t>> __M_task_pool;
    std::list<std::unique_ptr<task_t>> __M_outstanding_task_list;

    static_assert(
        std::is_nothrow_destructible_v<task_t> &&
        std::is_nothrow_destructible_v<decltype(__M_outstanding_task_list)>);

  protected:
    task_t* acquire() {
        try {
            task_t* r = nullptr;
            if (!__M_task_pool.empty()) {
                std::unique_ptr ptr = std::move(__M_task_pool.front());
                __M_task_pool.pop();
                r = __M_outstanding_task_list.emplace_front(std::move(ptr))
                        .get();
                r->reset();
            } else {
                r = __M_outstanding_task_list.emplace_front(new task_t(this))
                        .get();
            }
            r->__M_avail = false;
            r->__M_location = __M_outstanding_task_list.begin();
            return r;
        } catch (const std::exception&) {
            rethrow_with_fatal(std::make_exception_ptr(
                __CHXNET_MAKE_EX_CSTR("failed to obtain a task_t")));
        }
    }

    void release(task_t* task) noexcept(true) {
        auto loc = task->__M_location;
        std::unique_ptr ptr = std::move(*loc);
        __M_outstanding_task_list.erase(loc);
        if (__M_task_pool.size() < 256) {
            __M_task_pool.push(std::move(ptr));
        }
    }

    [[nodiscard]] io_uring_sqe* get_sqe(task_t* task = nullptr) {
        auto* sqe = io_uring_get_sqe(&__M_ring);
        if (sqe) {
            io_uring_sqe_set_data(sqe, task);
            return sqe;
        } else {
            submit();
            sqe = io_uring_get_sqe(&__M_ring);
            if (sqe) {
                io_uring_sqe_set_data(sqe, task);
                return sqe;
            } else {
                rethrow_with_fatal(std::make_exception_ptr(
                    __CHXNET_MAKE_EX_CSTR("Cannot obtain io_uring_sqe*")));
            }
        }
    }

    [[nodiscard]] io_uring_sqe*
    try_get_sqe(task_t* task = nullptr) noexcept(true) {
        auto* sqe = io_uring_get_sqe(&__M_ring);
        if (sqe) {
            io_uring_sqe_set_data(sqe, task);
        }
        return sqe;
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
        submit();
    }

    template <typename... Signature, typename FinalFunctor,
              typename CompletionToken>
    decltype(auto) async_delivery(FinalFunctor&& final_functor,
                                  CompletionToken&& completion_token);

  private:
    void __advance(unsigned int nr) noexcept(true) {
        io_uring_cq_advance(&__M_ring, nr);
    }

    void __run() {
        while (outstanding_tasks()) {
            if (int r = io_uring_submit_and_wait(&__M_ring, 1); r < 0) {
                rethrow_with_fatal(std::make_exception_ptr(
                    __CHXNET_MAKE_EX_CSTR("io_uring_submit_and_wait failed")));
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
                    assert(!(cqe->flags & IORING_CQE_F_NOTIF));
                    auto* task =
                        static_cast<task_t*>(io_uring_cqe_get_data(cqe));

                    if (task->__M_notif && task->__M_persist) {
                        // if task is aware of notif
                        try {
                            task->__M_token(task);
                        } catch (const std::exception&) {
                            release(task);
                            std::rethrow_exception(std::current_exception());
                        }
                    } else {
                        // if this cqe is not notif
                        // res of notif is zero
                        if ((cqe->flags & IORING_CQE_F_NOTIF) == 0) {
                            task->__M_res = cqe->res;
                            if (cqe->res < 0) {
                                detail::assign_ec(task->__M_ec, -cqe->res);
                            } else {
                                task->__M_ec.clear();
                            }
                        }
                        // if there is no more cqe
                        if ((cqe->flags & IORING_CQE_F_MORE) == 0) {
                            bool _need_release = !task->__M_persist;
                            try {
                                task->__M_token(task);
                            } catch (const std::exception&) {
                                release(task);
                                std::rethrow_exception(
                                    std::current_exception());
                            }
                            if (_need_release) {
                                release(task);
                            }
                        }
                    }
                }
                if (is_stopped()) {
                    return;
                }
            }
        }
    }

    void __async_cancel_all() {
        for (auto& ptr : __M_outstanding_task_list) {
            auto* sqe = get_sqe();
            io_uring_prep_cancel(sqe, ptr.get(), IORING_ASYNC_CANCEL_ALL);
        }
    }

    void submit() {
        if (int r = io_uring_submit(&__M_ring); r >= 0) {
            return;
        } else {
            rethrow_with_fatal(std::make_exception_ptr(
                __CHXNET_MAKE_EX_CSTR("io_uring_submit failed")));
        }
    }

  public:
    io_context(std::size_t static_task_sz = 1024 * 1024 * 2 / sizeof(task_t))
    /*: __M_static_task_sz(static_task_sz)*/ {
        // __M_mt_closed.test_and_set(std::memory_order_acquire);

        struct io_uring_params params = {};
        // params.flags |= IORING_SETUP_SQPOLL;
        params.features |= IORING_FEAT_FAST_POLL | IORING_FEAT_CQE_SKIP;
        if (int r = io_uring_queue_init_params(
                static_task_sz > 4096 ? static_task_sz : 4096, &__M_ring,
                &params);
            r != 0) {
            rethrow_with_fatal(std::make_exception_ptr(
                __CHXNET_MAKE_EX_CSTR("io_uring_queue_init_params failed")));
        }
    }

    /**
     * @brief Destroy the io_context object.
     *
     */
    ~io_context() {
        io_uring_queue_exit(&__M_ring);
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

    std::size_t outstanding_tasks() const noexcept(true) {
        return __M_outstanding_task_list.size();
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
