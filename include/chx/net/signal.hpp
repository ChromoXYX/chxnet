#pragma once

#include "./io_context.hpp"
#include "./attribute.hpp"
#include "./file_descriptor.hpp"

// TODO: change poll to read, poll may be useless here.

#include <poll.h>
#include <sys/signalfd.h>
#include <csignal>

namespace chx::net {
class signal;

namespace detail {
namespace tags {
struct signal_cancel {};
struct signal_wait {};
}  // namespace tags

template <> struct async_operation<tags::signal_cancel> {
    void operator()(io_context* ctx, int fd) const {
        auto* sqe = ctx->get_sqe();
        io_uring_prep_cancel_fd(sqe, fd, IORING_ASYNC_CANCEL_ALL);
        sqe->flags = IOSQE_CQE_SKIP_SUCCESS;
    }
};

template <> struct async_operation<tags::signal_wait> {
    template <typename CompletionToken>
    decltype(auto) operator()(io_context* ctx, signal* sig,
                              CompletionToken&& completion_token);
};
}  // namespace detail

/**
 * @brief Object to handle signal related async tasks.
 *
 */
class signal {
    friend detail::async_operation<detail::tags::signal_wait>;

    io_context* const __M_ctx;

    sigset_t __M_sigset = {};
    bool __M_sync = false;
    bool __M_keep = false;
    int __M_sigfd = -1;

    void __clean_mask() noexcept(true) {
        __M_sync = false;
        sigset_t set = {};
        sigemptyset(&set);
        sigprocmask(SIG_SETMASK, &set, nullptr);
    }
    void __clean_fd() noexcept(true) {
        __M_sync = false;
        sigset_t set = {};
        sigemptyset(&set);
        signalfd(__M_sigfd, &set, 0);
    }

    template <typename CntlType = int> struct operation {
        template <typename T> using rebind = operation<T>;

        signal* self = nullptr;
        file_descriptor_view fd;
        struct signalfd_siginfo sigbuf = {};

        constexpr operation(signal* s) noexcept(true)
            : self(s), fd(self->get_associated_io_context(), self->__M_sigfd) {}

        void operator()(CntlType& cntl) {
            fd.async_read_some(buffer(&sigbuf, sizeof(sigbuf)), cntl.next());
        }
        void operator()(CntlType& cntl, const std::error_code& e,
                        std::size_t s) {
            cntl.complete(e, sigbuf.ssi_signo);
        }
    };

  public:
    /**
     * @brief Construct a new signal object.
     *
     * @param ctx The associated io_context.
     */
    signal(io_context& ctx) noexcept(true) : __M_ctx(&ctx) {
        sigemptyset(&__M_sigset);
    }
    /**
     * @brief Construct a new signal object
     *
     * @param ctx The associated io_context.
     * @param signal_list Brace-enclosed list of signals to be added into the
     * signal set.
     */
    signal(io_context& ctx, std::initializer_list<int> signal_list)
        : signal(ctx) {
        for (auto sig : signal_list) {
            add(sig);
        }
    }
    /**
     * @brief Destroy the signal object.
     *
     */
    ~signal() {
        std::error_code ec;
        cancel();
        if (is_open()) {
            close(ec);
        }
    }

    /**
     * @brief Get the associated io_context object
     *
     * @return constexpr io_context&
     */
    constexpr io_context& get_associated_io_context() noexcept(true) {
        return *__M_ctx;
    }

    /**
     * @brief Add a signal to the signal set.
     *
     * @param signal
     * @return int
     */
    int add(int signal) noexcept(true) {
        __M_sync = false;
        return sigaddset(&__M_sigset, signal);
    }
    /**
     * @brief Remove a signal from the signal set.
     *
     * @param signal
     * @return int
     */
    int del(int signal) noexcept(true) {
        __M_sync = false;
        return sigdelset(&__M_sigset, signal);
    }
    /**
     * @brief Clear the signal set.
     *
     * @return int
     */
    int clear() noexcept(true) {
        __M_sync = false;
        return sigemptyset(&__M_sigset);
    }

    /**
     * @brief Check whether the underlying signal notification file descriptor
     * is available.
     *
     * @return true
     * @return false
     */
    bool is_open() noexcept(true) {
        return __M_sigfd > 0 &&
               (::fcntl(__M_sigfd, F_GETFD) != -1 || errno != EBADF);
    }

    /**
     * @brief Cancel all async tasks associated with the signal object.
     *
     */
    void cancel() {
        detail::async_operation<detail::tags::signal_cancel>()(
            &get_associated_io_context(), __M_sigfd);
    }

    /**
     * @brief Close the underlying signal notification file descriptor.
     *
     * @param ec The error_code which carries error information.
     */
    void close(std::error_code& ec) noexcept(true) {
        __clean_mask();
        if (::close(__M_sigfd) == 0) {
            ec.clear();
        } else {
            detail::assign_ec(ec, errno);
        }
        __M_sigfd = -1;
        __M_sync = false;
    }
    /**
     * @brief Close the underlying signal notification file descriptor.
     *
     */
    void close() {
        std::error_code ec;
        close(ec);
        if (ec) {
            __CHXNET_THROW_EC(ec);
        }
    }

    /**
     * @brief Submit an async task waiting for signals.
     *
     * @param completion_token Callable object with signature
     * \code
     * void(const std::error_code&, int)
     * \endcode
     * @return decltype(auto)
     */
    template <typename CompletionToken>
    decltype(auto) async_wait(CompletionToken&& completion_token) {
        if (!__M_sync) {
            std::error_code ec;
            if (sigprocmask(SIG_SETMASK, &__M_sigset, nullptr) == -1) {
                // if failed to set signal block mask.
                close(ec);
                __CHXNET_THROW(errno);
            }
            if (!is_open() &&
                ((__M_sigfd = signalfd(__M_sigfd, &__M_sigset, 0)) == -1)) {
                // if current signalfd is not open, and failed to get a new
                // signalfd.
                __clean_mask();
                __CHXNET_THROW(errno);
            } else if (signalfd(__M_sigfd, &__M_sigset, 0) == -1) {
                // if failed to update current signalfd.
                close(ec);
                __CHXNET_THROW(errno);
            }
            __M_sync = true;
        }
        return async_combine<const std::error_code&, int>(
            get_associated_io_context(),
            std::forward<CompletionToken>(completion_token),
            detail::type_identity<operation<>>{}, this);
    }
};
}  // namespace chx::net
