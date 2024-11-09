#pragma once

#include <cassert>
#include <liburing.h>
#include <sys/eventfd.h>

#include <memory>
#include <queue>
#include <algorithm>

#include "./detail/task_declare.hpp"
#include "./detail/basic_token_storage.hpp"
#include "./detail/noncopyable.hpp"
#include "./detail/interrupter.hpp"
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
struct interrupter {};
}  // namespace tags

struct task_declare::task_decl {
    CHXNET_NONCOPYABLE
    struct cancellation_controller_base {
        virtual void operator()(cancellation_signal&) = 0;
        virtual void cancel(task_decl*) = 0;
        virtual ~cancellation_controller_base() = default;
    };

    task_decl(io_context* p) noexcept(true) : __M_ctx(p) {}

    io_context* __M_ctx = nullptr;

    std::uint64_t __M_additional = {};

    bool __M_avail = true;
    bool __M_option1 = false;
    union {
        bool __M_notif = false;
        bool __M_persist;
    };
    enum __CancelType : std::uint8_t {
        __CT_io_uring_based,
        __CT_invoke_cancel,
        __CT_no_cancel
    } __M_cancel_type = __CT_io_uring_based;
    bool __M_option5 = false;
    bool __M_option6 = false;
    bool __M_option7 = false;

    std::error_code __M_ec;
    int __M_res;

    std::unique_ptr<cancellation_controller_base> __M_custom_cancellation;

    detail::basic_token_storage<int(task_decl*), CHXNET_TOKEN_STORAGE_SIZE>
        __M_token;

    void reset() noexcept(true) {
        __M_ec.clear();
        __M_res = 0;
        __M_notif = false;
        __M_cancel_type = __CT_io_uring_based;

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

class io_context {
    CHXNET_NONCOPYABLE

    template <typename Tag> friend struct detail::async_operation;

  public:
    /**
     * @brief Type which carries necessary data for a single async task.
     *
     */
    using task_t = detail::task_declare::task_decl;

  protected:
    struct message_base {
        virtual ~message_base() = default;
        virtual void operator()(io_context*) = 0;
    };

    io_uring __M_ring;
    bool __M_stopped = false;
    const std::size_t __M_ring_sz;

    std::queue<std::unique_ptr<task_t>> __M_task_pool;
    std::vector<std::unique_ptr<task_t>> __M_outstanding_task_list;

    alignas(64) std::mutex __M_msg_list_mutex;
    alignas(64) std::atomic_bool __M_msg_list_empty = false;
    std::vector<std::unique_ptr<message_base>> __M_msg_list;

    static_assert(
        std::is_nothrow_destructible_v<task_t> &&
        std::is_nothrow_destructible_v<decltype(__M_outstanding_task_list)>);

    detail::interrupter __M_interrupter;

  protected:
    task_t* acquire() {
        try {
            task_t* r = nullptr;
            if (!__M_task_pool.empty()) {
                std::unique_ptr ptr = std::move(__M_task_pool.front());
                __M_task_pool.pop();
                r = __M_outstanding_task_list.emplace_back(std::move(ptr))
                        .get();
                r->reset();
            } else {
                r = __M_outstanding_task_list.emplace_back(new task_t(this))
                        .get();
            }
            r->__M_avail = false;
            return r;
        } catch (const std::exception&) {
            rethrow_with_fatal(std::make_exception_ptr(
                __CHXNET_MAKE_EX_CSTR("failed to obtain a task_t")));
        }
    }

    void release(task_t* task) noexcept(true) {
        auto loc = std::find_if(__M_outstanding_task_list.begin(),
                                __M_outstanding_task_list.end(),
                                [&](const auto& p) { return p.get() == task; });
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
        task->__M_res = cqe->res;
        if (task->__M_notif) {
            // if task is aware of notif, or is persist
            task->__M_token(task);
        } else {
            assert(!(cqe->flags & IORING_CQE_F_MORE));
            if (cqe->res < 0) {
                assign_ec(task->__M_ec, -cqe->res);
            } else {
                task->__M_ec.clear();
            }
            try {
                task->__M_token(task);
            } catch (const std::exception&) {
                release(task);
                std::rethrow_exception(std::current_exception());
            }
            release(task);
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
            try {
                for (; i < v.size(); ++i) {
                    (*v[i])(this);
                    v[i].reset();
                }
            } catch (const std::exception& ex) {
                if (i + 1 < v.size()) {
                    std::lock_guard lg(__M_msg_list_mutex);
                    __M_msg_list.insert(
                        __M_msg_list.end(),
                        std::make_move_iterator(v.begin() + i + 1),
                        std::make_move_iterator(v.end()));
                    __M_msg_list_empty.store(false, std::memory_order_relaxed);
                }
            }
        }
    }

    void __run() {
        while (outstanding_tasks()) {
            if (int r = io_uring_submit_and_wait(&__M_ring, 1); r < 0) {
                // rethrow_with_fatal(std::make_exception_ptr(
                //     __CHXNET_MAKE_EX_CSTR("io_uring_submit_and_wait
                //     failed")));
                continue;
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
                    } else {
                        __handle_task(cqe);
                    }
                }
                if (is_stopped()) {
                    return;
                }
                if (nr.nr > __M_ring_sz) {
                    break;
                }
            }
        }
        __handle_msg();
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
        : __M_ring_sz(static_task_sz > 4096 ? static_task_sz : 4096) {
        struct io_uring_params params = {};
        params.features |= IORING_FEAT_FAST_POLL | IORING_FEAT_CQE_SKIP;
        if (int r = io_uring_queue_init_params(__M_ring_sz, &__M_ring, &params);
            r != 0) {
            rethrow_with_fatal(std::make_exception_ptr(
                __CHXNET_MAKE_EX_CSTR("io_uring_queue_init_params failed")));
        }
        __M_interrupter.do_read(get_sqe(), &__M_interrupter);
    }

    /**
     * @brief Destroy the io_context object.
     *
     */
    ~io_context() { io_uring_queue_exit(&__M_ring); }
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

    template <typename Fn> void post(Fn&& fn) {
        using __decay_t = std::decay_t<Fn>;
        struct impl : message_base, __decay_t {
            impl(Fn&& fn) : __decay_t(std::forward<Fn>(fn)) {}

            void operator()(io_context* ctx) override {
                if constexpr (std::is_invocable_v<Fn&&, io_context*>) {
                    __decay_t::operator()(ctx);
                } else {
                    __decay_t::operator()();
                }
            }
        };
        std::unique_ptr<message_base> msg =
            std::make_unique<impl>(std::forward<Fn>(fn));
        std::lock_guard lg(__M_msg_list_mutex);
        __M_msg_list.emplace_back(std::move(msg));
        __M_msg_list_empty.store(false, std::memory_order_relaxed);
    }
    void interrupt() const { __M_interrupter.do_interrupt(); }

    constexpr std::size_t outstanding_tasks() const noexcept(true) {
        return __M_outstanding_task_list.size();
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
