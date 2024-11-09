#pragma once

#include "./detail/noncopyable.hpp"
#include "./detail/interrupter.hpp"

namespace chx::net {
template <typename MessageQueue> class basic_thread_context : MessageQueue {
    CHXNET_NONCOPYABLE

    io_uring __M_ring;
    detail::interrupter __M_interrupter;

    void __submit() {
        if (int r = io_uring_submit(&__M_ring); r >= 0) {
            return;
        } else {
            rethrow_with_fatal(std::make_exception_ptr(
                __CHXNET_MAKE_EX_CSTR("io_uring_submit failed")));
        }
    }
    [[nodiscard]] io_uring_sqe* __get_sqe() {
        auto* sqe = io_uring_get_sqe(&__M_ring);
        if (sqe) {
            return sqe;
        } else {
            __submit();
            sqe = io_uring_get_sqe(&__M_ring);
            if (sqe) {
                return sqe;
            } else {
                rethrow_with_fatal(std::make_exception_ptr(
                    __CHXNET_MAKE_EX_CSTR("Cannot obtain io_uring_sqe*")));
            }
        }
    }

  public:
    template <typename... Ts>
    basic_thread_context(Ts&&... ts) : MessageQueue(std::forward<Ts>(ts)...) {
        struct io_uring_params params = {};
        params.features |= IORING_FEAT_FAST_POLL | IORING_FEAT_CQE_SKIP;
        if (int r = io_uring_queue_init_params(4096, &__M_ring, &params);
            r != 0) {
            rethrow_with_fatal(std::make_exception_ptr(
                __CHXNET_MAKE_EX_CSTR("io_uring_queue_init_params failed")));
        }
        __M_interrupter.do_read(__get_sqe(), &__M_interrupter);
    }
    ~basic_thread_context() { io_uring_queue_exit(&__M_ring); }

    void run_once() {
        io_uring_cqe* cqe;
        if (io_uring_wait_cqe(&__M_ring, &cqe)) {
            rethrow_with_fatal(std::make_exception_ptr(
                __CHXNET_MAKE_EX_CSTR("io_uring_wait_cqe failed")));
        }
        io_uring_cqe_seen(&__M_ring, cqe);
        MessageQueue::operator()();
    }

    void interrupt() const { __M_interrupter.do_interrupt(); }
};
}  // namespace chx::net
