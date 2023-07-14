#pragma once

#include <liburing.h>

#include <cassert>
#include <memory>
#include <vector>

#include "./detail/basic_token_storage.hpp"
#include "./detail/noncopyable.hpp"
#include "./error_code.hpp"

#include <cstdint>

#ifndef CHXNET_TOKEN_STORAGE_SIZE
#define CHXNET_TOKEN_STORAGE_SIZE 48
#endif

#ifndef CHXNET_ENABLE_SQPOLL
#define CHXNET_ENABLE_SQPOLL 1
#endif

namespace chx::net {
class bad_io_uring_init : public exception {
  public:
    using exception::exception;
};
class bad_io_context_exec : public exception {
  public:
    using exception::exception;
};

namespace detail {
template <typename Tag> struct async_operation;
namespace tags {
struct use_delivery {};
}  // namespace tags
}  // namespace detail

class io_context : CHXNET_NONCOPYABLE {
    template <typename Tag> friend struct detail::async_operation;

  public:
    io_uring __M_ring;
    bool __M_stopped = false;
    bool __M_destructing = false;

    struct __task_t : CHXNET_NONCOPYABLE {
        __task_t(io_context* p) noexcept(true) : __M_ctx(p) {}

        io_context* __M_ctx = nullptr;

        std::uint64_t __M_additional = {};

        bool __M_static = true;

        bool __M_avail = true;
        bool __M_persist = false;
        bool __M_notif = false;
        bool __M_cancel_invoke = false;
        bool __M_option5 = true;
        bool __M_option6 = true;
        bool __M_option7 = true;
        std::size_t __M_dyn_idx = 0;

        std::error_code __M_ec;
        int __M_res;

        detail::basic_token_storage<int(__task_t*), CHXNET_TOKEN_STORAGE_SIZE>
            __M_token;

        void reset() noexcept(true) {
            __M_token.clear();
            __M_ec.clear();
            __M_res = 0;
            __M_persist = false;
            __M_notif = false;
            __M_cancel_invoke = false;
        }

        constexpr io_context& get_associated_io_context() noexcept(true) {
            return *__M_ctx;
        }
        void* get_underlying_data() noexcept(true) {
            return __M_token.underlying_data();
        }
    };
    __task_t* __M_static_task_queue = nullptr;
    const std::size_t __M_static_task_sz;
    std::size_t __M_static_total = 0;
    std::size_t __M_last_static = 0;

    std::vector<std::unique_ptr<__task_t>> __M_dynamic_task_queue;
    std::size_t __M_dyn_total = 0;
    std::size_t __M_dyn_end = 0;

    static_assert(
        std::is_nothrow_destructible_v<__task_t> &&
        std::is_nothrow_destructible_v<decltype(__M_dynamic_task_queue)>);

  public:
    /**
     * @brief Type which carries necessary data for a single async task.
     *
     */
    using task_t = __task_t;

  protected:
    __task_t* acquire() {
        if (__M_static_total < __M_static_task_sz) {
            for (std::size_t i = __M_static_total < 128 ? 0
                                                        : __M_last_static + 1;
                 i < __M_static_task_sz; ++i) {
                if (__M_static_task_queue[i].__M_avail) {
                    __M_static_task_queue[i].__M_avail = false;
                    ++__M_static_total;
                    __M_last_static = i;
                    return &__M_static_task_queue[i];
                }
            }
            for (std::size_t i = 0; i < __M_last_static; ++i) {
                if (__M_static_task_queue[i].__M_avail) {
                    __M_static_task_queue[i].__M_avail = false;
                    ++__M_static_total;
                    __M_last_static = i;
                    return &__M_static_task_queue[i];
                }
            }
        } else {
            if (__M_dyn_total < __M_dynamic_task_queue.size()) {
                for (std::size_t idx = 0; idx < __M_dyn_end + 1; ++idx) {
                    if (__M_dynamic_task_queue[idx]->__M_avail) {
                        auto* p = __M_dynamic_task_queue[idx].get();
                        ++__M_dyn_total;
                        p->__M_avail = false;
                        return p;
                    }
                }
            } else {
                __M_dynamic_task_queue.emplace_back(new __task_t(this));

                ++__M_dyn_total;
                __M_dyn_end = __M_dynamic_task_queue.size() - 1;

                auto* p = __M_dynamic_task_queue.back().get();
                p->__M_avail = false;
                p->__M_static = false;
                p->__M_dyn_idx = __M_dyn_end;
                return p;
            }
        }
        __CHXNET_THROW_WITH(errc::internal_error, bad_io_context_exec);
    }

    void submit() {
        if (int r = io_uring_submit(&__M_ring); r >= 0) {
            return;
        } else {
            __CHXNET_THROW_WITH(-r, bad_io_context_exec);
        }
    }

    void release(__task_t* task) noexcept(true) {
        if (task->__M_static) {
            --__M_static_total;
            task->__M_avail = true;
            task->reset();
        } else {
            --__M_dyn_total;
            if (__M_dyn_total == 0) {
                __M_dyn_end = 0;
                __M_dynamic_task_queue.clear();
                return;
            }
            task->__M_avail = true;
            if (task->__M_dyn_idx == __M_dyn_end) {
                std::size_t idx = __M_dyn_end - 1;
                for (; idx; --idx) {
                    if (!__M_dynamic_task_queue[idx]->__M_avail) {
                        break;
                    }
                }
                __M_dyn_end = idx;
                __M_dynamic_task_queue.erase(__M_dynamic_task_queue.begin() +
                                                 idx + 1,
                                             __M_dynamic_task_queue.end());
            } else {
                task->reset();
            }
        }
    }

    [[nodiscard]] io_uring_sqe* get_sqe(__task_t* task = nullptr) {
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
                __CHXNET_THROW_WITH(errc::internal_error, bad_io_context_exec);
            }
        }
    }

    [[nodiscard]] io_uring_sqe*
    try_get_sqe(__task_t* task = nullptr) noexcept(true) {
        auto* sqe = io_uring_get_sqe(&__M_ring);
        if (sqe) {
            io_uring_sqe_set_data(sqe, task);
        }
        return sqe;
    }

    [[nodiscard]] std::pair<io_uring_sqe*, __task_t*> get() {
        std::pair<io_uring_sqe*, __task_t*> _r{get_sqe(), acquire()};
        io_uring_sqe_set_data(_r.first, _r.second);
        return _r;
    }
    void get(io_uring_sqe** sqe, __task_t** task) {
        *sqe = get_sqe();
        *task = acquire();
        io_uring_sqe_set_data(*sqe, *task);
    }
    void cancel_task(__task_t* task, int flags = 0) {
        auto* sqe = get_sqe();
        io_uring_prep_cancel(sqe, task, flags);
        sqe->flags = IOSQE_CQE_SKIP_SUCCESS;
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
        while (__M_static_total || __M_dyn_total) {
            if (int r = io_uring_submit_and_wait(&__M_ring, 1); r < 0) {
                __CHXNET_THROW_WITH(-r, bad_io_context_exec);
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
                    auto* task =
                        static_cast<__task_t*>(io_uring_cqe_get_data(cqe));

                    if (task->__M_notif && task->__M_persist) {
                        // if task is aware of notif
                        try {
                            task->__M_token(task);
                        } catch (...) {
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
                            } catch (...) {
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
        // auto* sqe = get_sqe();
        // io_uring_prep_cancel(sqe, nullptr, IORING_ASYNC_CANCEL_ANY);
        // sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
        // io_uring_sqe_set_data(sqe, nullptr);
        for (std::size_t idx = 0; idx < __M_static_task_sz; ++idx) {
            if (!__M_static_task_queue[idx].__M_avail) {
                auto* sqe = get_sqe();
                io_uring_prep_cancel(sqe, &__M_static_task_queue[idx],
                                     IORING_ASYNC_CANCEL_ALL);
            }
        }
        for (auto& ptr : __M_dynamic_task_queue) {
            auto* sqe = get_sqe();
            io_uring_prep_cancel(sqe, ptr.get(), IORING_ASYNC_CANCEL_ALL);
        }
    }

  public:
    /**
     * @brief Construct a new io_context object.
     *
     * @details IORING_SETUP_SQPOLL will be set if current process in running by
     * root user.
     *
     * @param static_task_sz Number of async tasks which will be allocated and
     * constructed along with io_context, to avoid massive allocation and
     * deallocation. Default value is 16384 in 64 bits OS, for 2MB in bytes.
     *
     */
    io_context(std::size_t static_task_sz = 1024 * 1024 * 2 / sizeof(__task_t))
        : __M_static_task_sz(static_task_sz) {
        struct io_uring_params params = {};
#if CHXNET_ENABLE_SQPOLL
        if (getuid() == 0) {
            params.flags |= IORING_SETUP_SQPOLL;
        }
#endif
        params.features |= IORING_FEAT_FAST_POLL | IORING_FEAT_CQE_SKIP;
        if (int r = io_uring_queue_init_params(
                static_task_sz > 4096 ? static_task_sz : 4096, &__M_ring,
                &params);
            r != 0) {
            __CHXNET_THROW_WITH(-r, bad_io_uring_init);
        }

        __M_static_task_queue =
            static_cast<__task_t*>(::malloc(sizeof(__task_t) * static_task_sz));
        if (__M_static_task_queue == nullptr) {
            __CHXNET_THROW_WITH(errc::internal_error, bad_io_context_exec);
        }

        for (std::size_t i = 0; i < static_task_sz; ++i) {
            auto* p = ::new (&__M_static_task_queue[i]) __task_t(this);
            p->__M_avail = true;
            p->__M_static = true;
        }
    }

    /**
     * @brief Destroy the io_context object.
     *
     */
    ~io_context() {
        __M_destructing = true;
        try {
            while (!is_stopped() &&
                   (__M_static_total || !__M_dynamic_task_queue.empty())) {
                __async_cancel_all();
                __run();
            }
        } catch (...) {
            io_uring_queue_exit(&__M_ring);
            std::destroy(__M_static_task_queue,
                         __M_static_task_queue + __M_static_task_sz);
            ::free(__M_static_task_queue);
            std::rethrow_exception(std::current_exception());
        }
        io_uring_queue_exit(&__M_ring);
        std::destroy(__M_static_task_queue,
                     __M_static_task_queue + __M_static_task_sz);
        ::free(__M_static_task_queue);
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
