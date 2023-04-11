#pragma once

#include "./io_context.hpp"
#include "./attribute.hpp"

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
struct signal_failed {};
}  // namespace tags

template <> struct async_operation<tags::signal_cancel> {
    void operator()(io_context* ctx, int fd) const {
        if (!ctx->is_closed()) {
            auto* sqe = ctx->get_sqe();
            io_uring_prep_cancel_fd(sqe, fd, IORING_ASYNC_CANCEL_ALL);
            sqe->flags = IOSQE_CQE_SKIP_SUCCESS;
        }
    }
};

template <> struct async_operation<tags::signal_wait> {
    template <typename CompletionToken>
    decltype(auto) operator()(io_context* ctx, signal* sig,
                              CompletionToken&& completion_token);
};

template <typename FinalFunctor, typename BaseCT>
struct signal_failed_final : FinalFunctor, BaseCT {
    int error = 0;

    template <typename F, typename T>
    constexpr signal_failed_final(F&& f, T&& t, int e)
        : FinalFunctor(std::forward<F>(f)), BaseCT(std::forward<T>(t)),
          error(e) {}

    int operator()(io_context::task_t* self) {
        auto fn = [this](const std::error_code& ec) mutable {
            return static_cast<BaseCT&>(*this)(
                ec ? ec : detail::make_ec(this->error), this->error);
        };
        return FinalFunctor::operator()(fn, self);
    }
};
template <typename FinalFunctor, typename BaseCT>
signal_failed_final(FinalFunctor&&, BaseCT&&, int)
    -> signal_failed_final<std::remove_reference_t<FinalFunctor>,
                           std::remove_reference_t<BaseCT>>;

template <typename T> struct signal_failed {
    using attribute_type = attribute<async_token>;

    T t;
    int error;

    template <typename CompletionToken>
    constexpr signal_failed(int e,
                            CompletionToken&& completion_token) noexcept(true)
        : error(e), t(std::forward<CompletionToken>(completion_token)) {}

    template <typename... Signature>
    constexpr decltype(auto) bind() noexcept(true) {
        return *this;
    }

    template <typename FinalFunctor>
    decltype(auto) generate_token(io_context::task_t* task,
                                  FinalFunctor&& final_functor) {
        return signal_failed_final(
            std::forward<FinalFunctor>(final_functor),
            detail::async_token_generate(task, __CHXNET_FAKE_FINAL_FUNCTOR(),
                                         t)(nullptr),
            error);
    }

    template <typename TypeIdentity> decltype(auto) get_init(TypeIdentity ti) {
        return detail::async_token_init(ti, t);
    }
};
template <typename CompletionToken>
signal_failed(int, CompletionToken&&)
    -> signal_failed<std::remove_reference_t<CompletionToken>>;

template <typename CompletionToken>
constexpr decltype(auto)
make_signal_failed(int error, CompletionToken&& completion_token) {
    if constexpr (is_async_token<std::decay_t<CompletionToken>>::value) {
        return signal_failed(
            error, detail::async_token_bind<const std::error_code&, int>(
                       std::forward<CompletionToken>(completion_token)));
    } else {
        return
            [completion_token = std::forward<CompletionToken>(completion_token),
             error](const std::error_code& ec) mutable {
                completion_token(ec ? ec : detail::make_ec(error), 0);
            };
    }
}
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
        return __M_sigfd != -1 &&
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
                return __M_ctx->async_nop(detail::make_signal_failed(
                    errno, std::forward<CompletionToken>(completion_token)));
            }
            if (!is_open() &&
                ((__M_sigfd = signalfd(-1, &__M_sigset, 0)) == -1)) {
                // if current signalfd is not open, and failed to get a new
                // signalfd.
                __clean_mask();
                return __M_ctx->async_nop(detail::make_signal_failed(
                    errno, std::forward<CompletionToken>(completion_token)));

            } else if (signalfd(__M_sigfd, &__M_sigset, 0) == -1) {
                // if failed to update current signalfd.
                close(ec);
                return __M_ctx->async_nop(detail::make_signal_failed(
                    errno, std::forward<CompletionToken>(completion_token)));
            }
            __M_sync = true;
        }
        return detail::async_operation<detail::tags::signal_wait>()(
            &get_associated_io_context(), this,
            detail::async_token_bind<const std::error_code&, int>(
                std::forward<CompletionToken>(completion_token)));
    }
};
}  // namespace chx::net

template <typename CompletionToken>
decltype(auto)
chx::net::detail::async_operation<chx::net::detail::tags::signal_wait>::
operator()(io_context* ctx, signal* sig, CompletionToken&& completion_token) {
    io_context::task_t* task =
        ctx->is_closed() ? ctx->acquire_after_close() : ctx->acquire();
    if (!ctx->is_closed()) {
        auto* sqe = ctx->get_sqe(task);
        io_uring_prep_poll_add(sqe, sig->__M_sigfd, POLLIN);
    }

    task->__M_additional = reinterpret_cast<std::uint64_t>(sig);
    sig->__M_keep = true;
    return detail::async_token_init(
        task->__M_token.emplace(detail::async_token_generate(
            task,
            [](auto& completion_token,
               io_context::task_t* self) mutable -> int {
                auto* sig = reinterpret_cast<signal*>(self->__M_additional);

                int sigfd = sig->__M_sigfd;
                int signal = 0;
                if (!self->__M_ec) {
                    signalfd_siginfo info = {};
                    if (int r = read(sigfd, &info, sizeof(info));
                        r == sizeof(info)) {
                        signal = info.ssi_signo;
                    } else {
                        detail::assign_ec(self->__M_ec, errno);
                    }
                }
                sig->__M_keep = false;
                completion_token(self->__M_ec, signal);
                if (!sig->__M_keep) {
                    sig->__clean_mask();
                    if (sig->is_open()) {
                        sig->__clean_fd();
                    }
                }
                return 0;
            },
            std::forward<CompletionToken>(completion_token))),
        std::forward<CompletionToken>(completion_token));
}
