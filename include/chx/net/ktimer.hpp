#pragma once

#include <chrono>
#include <sys/timerfd.h>

#include "./io_context.hpp"

#include "./detail/io_uring_task_getter.hpp"

namespace chx::net::detail::tags {
struct ktimer {};
}  // namespace chx::net::detail::tags

template <>
struct chx::net::detail::async_operation<chx::net::detail::tags::ktimer> {
    template <typename CompletionToken>
    decltype(auto) operator()(io_context*, int, CompletionToken&&) const;

    void cancel(io_context* ctx, int fd) const {
        auto* sqe = ctx->get_sqe();
        io_uring_prep_cancel_fd(sqe, fd, IORING_ASYNC_CANCEL_ALL);
        io_uring_sqe_set_data(sqe, nullptr);
        sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
    }
};

namespace chx::net {
class bad_ktimer : public exception {
  public:
    using exception::exception;
};

class ktimer {
    CHXNET_NONCOPYABLE

    io_context* __M_ctx;
    int __M_fd = -1;

  public:
    ktimer(io_context& ctx) : __M_ctx(&ctx) {
        __M_fd = ::timerfd_create(CLOCK_REALTIME, 0);
        if (__M_fd == -1) {
            __CHXNET_THROW_WITH(errno, bad_ktimer);
        }
    }
    ktimer(ktimer&& other) noexcept(true)
        : __M_ctx(other.__M_ctx), __M_fd(std::exchange(other.__M_fd, -1)) {}
    ~ktimer() {
        if (is_open()) {
            ::close(native_handler());
        }
    }

    constexpr io_context& get_associated_io_context() noexcept(true) {
        return *__M_ctx;
    }
    constexpr int native_handler() const noexcept(true) { return __M_fd; }

    bool is_open() const noexcept(true) {
        return native_handler() > 0 &&
               (::fcntl(native_handler(), F_GETFD) || errno != EBADF);
    }

    template <typename Rep, typename Period>
    void expired_after(const std::chrono::duration<Rep, Period>& d,
                       std::error_code& ec) noexcept(true) {
        struct itimerspec its = {};
        auto secs = std::chrono::duration_cast<std::chrono::seconds>(d);

        its.it_value.tv_sec = secs.count();
        its.it_value.tv_nsec =
            std::chrono::duration_cast<std::chrono::nanoseconds>(d - secs)
                .count();

        if (::timerfd_settime(__M_fd, 0, &its, nullptr) == 0) {
            ec.clear();
        } else {
            assign_ec(ec, errno);
        }
    }
    template <typename Rep, typename Period>
    void expired_after(const std::chrono::duration<Rep, Period>& d) {
        std::error_code ec;
        expired_after(d, ec);
        if (ec) {
            __CHXNET_THROW_EC(ec);
        }
    }

    std::chrono::nanoseconds expired_after(std::error_code& ec) noexcept(true) {
        struct itimerspec its = {};
        std::chrono::nanoseconds remaining = std::chrono::nanoseconds::zero();
        if (::timerfd_gettime(__M_fd, &its) == 0) {
            remaining = std::chrono::seconds(its.it_value.tv_sec) +
                        std::chrono::nanoseconds(its.it_value.tv_nsec);
            ec.clear();
        } else {
            assign_ec(ec, errno);
        }
        return remaining;
    }
    std::chrono::nanoseconds expired_after() {
        std::error_code ec;
        auto r = expired_after(ec);
        if (ec) {
            __CHXNET_THROW_EC(ec);
        }
        return r;
    }

    template <typename CompletionToken>
    decltype(auto) async_wait(CompletionToken&& completion_token) {
        return detail::async_operation<detail::tags::ktimer>()(
            &get_associated_io_context(), __M_fd,
            detail::async_token_bind<const std::error_code&>(
                std::forward<CompletionToken>(completion_token)));
    }

    void cancel() {
        detail::async_operation<detail::tags::ktimer>().cancel(
            &get_associated_io_context(), __M_fd);
    }
};
}  // namespace chx::net

template <typename CompletionToken>
decltype(auto)
chx::net::detail::async_operation<chx::net::detail::tags::ktimer>::operator()(
    io_context* ctx, int fd, CompletionToken&& completion_token) const {
    io_context::task_t* task = ctx->acquire();
    auto* sqe = ctx->get_sqe(task);
    io_uring_prep_read(sqe, fd, &task->__M_additional_val, 8, 0);

    return detail::async_token_init(
        task->__M_token.emplace(detail::async_token_generate(
            task,
            [](auto& completion_token, io_context::task_t* self) -> int {
                completion_token(get_ec(self));
                return 0;
            },
            completion_token)),
        completion_token);
}
