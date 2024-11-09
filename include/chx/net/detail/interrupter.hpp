#pragma once

#include <sys/eventfd.h>
#include <unistd.h>
#include <liburing.h>
#include "../error_code.hpp"
#include "../exception.hpp"

namespace chx::net::detail {
struct interrupter {
    eventfd_t __M_efd = -1;

    interrupter() {
        __M_efd = eventfd(0, EFD_SEMAPHORE | EFD_NONBLOCK);
        if (__M_efd == -1) {
            rethrow_with_fatal(
                std::make_exception_ptr(__CHXNET_MAKE_EX_CODE(errno)));
        }
    }
    ~interrupter() noexcept(true) {
        if (__M_efd >= 0) {
            ::close(__M_efd);
        }
    }

    std::size_t __M_inbuf = 0;
    constexpr static inline std::size_t wr_buf = 1;

    void do_read(io_uring_sqe* sqe, void* user_data) {
        io_uring_prep_read(sqe, __M_efd, &__M_inbuf, 8, 0);
        io_uring_sqe_set_data(sqe, user_data);
    }
    void do_interrupt() const {
        int r = eventfd_write(__M_efd, 1);
        if (r == 0 || errno == EWOULDBLOCK) {
            return;
        } else {
            rethrow_with_fatal(
                std::make_exception_ptr(__CHXNET_MAKE_EX_CODE(errno)));
        }
    }
};
}  // namespace chx::net::detail