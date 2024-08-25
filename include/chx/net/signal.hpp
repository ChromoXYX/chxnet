#pragma once

#include "./io_context.hpp"
#include "./file_descriptor.hpp"

#include <sys/signalfd.h>

namespace chx::net {
class signal : CHXNET_NONCOPYABLE {
  protected:
    file_descriptor __M_fd;

    template <typename CntlType = int> struct operation {
        template <typename T> using rebind = operation<T>;

        signal* self = nullptr;
        signalfd_siginfo buf = {};

        operation(signal* s) noexcept(true) : self(s) {}

        void operator()(CntlType& cntl) {
            self->__M_fd.async_read_some(net::buffer(&buf, sizeof(buf)),
                                         cntl.next());
        }
        void operator()(CntlType& cntl, const std::error_code& e,
                        std::size_t s) {
            cntl.complete(e, !e ? buf.ssi_signo : -1);
        }
    };

    int setmask_errno(int how, const sigset_t* oldsig,
                      sigset_t* newsig) noexcept(true) {
        if (int r = pthread_sigmask(how, oldsig, newsig); r == 0) {
            return r;
        } else {
            errno = r;
            return -1;
        }
    }

  public:
    signal(io_context& ctx) : __M_fd(ctx) {
        sigset_t s = {};
        sigemptyset(&s);
        if (setmask_errno(SIG_SETMASK, &s, nullptr) == -1) {
            __CHXNET_THROW(errno);
        }
        if (int f = signalfd(-1, &s, 0); f != -1) {
            __M_fd.set_fd(f);
        } else {
            __CHXNET_THROW(errno);
        }
    }
    signal(io_context& ctx, std::initializer_list<int> list) : __M_fd(ctx) {
        sigset_t set = {};
        sigemptyset(&set);
        for (auto i : list) {
            if (sigaddset(&set, i) == -1) {
                __CHXNET_THROW(errno);
            }
        }
        if (setmask_errno(SIG_SETMASK, &set, nullptr) == -1) {
            __CHXNET_THROW(errno);
        }
        if (int f = signalfd(-1, &set, 0); f != -1) {
            __M_fd.set_fd(f);
        } else {
            __CHXNET_THROW(errno);
        }
    }

    constexpr io_context& get_associated_io_context() const noexcept(true) {
        return __M_fd.get_associated_io_context();
    }
    constexpr int native_handler() const noexcept(true) {
        return __M_fd.native_handler();
    }
    void close() noexcept(true) { __M_fd.close(); }

    void add(int sig, std::error_code& e) noexcept(true) {
        e.clear();
        if (sigset_t set = {};
            (setmask_errno(SIG_SETMASK, nullptr, &set) != -1) &&
            (sigaddset(&set, sig) != -1) &&
            (setmask_errno(SIG_SETMASK, &set, nullptr) != -1)) {
            if (int f = signalfd(__M_fd.native_handler(), &set, 0); f != -1) {
                if (__M_fd.native_handler() == -1) {
                    __M_fd.set_fd(f);
                }
            } else {
                detail::assign_ec(e, errno);
                __M_fd.close();
            }
            return;
        } else {
            detail::assign_ec(e, errno);
        }
    }
    void add(int sig) {
        std::error_code e;
        add(sig, e);
        if (e) {
            __CHXNET_THROW_EC(e);
        }
    }

    void del(int sig, std::error_code& e) noexcept(true) {
        e.clear();
        if (sigset_t set = {};
            setmask_errno(SIG_SETMASK, nullptr, &set) != -1) {
            switch (sigismember(&set, sig)) {
            case 1: {
                if (sigdelset(&set, sig) != -1) {
                    if (int f = signalfd(__M_fd.native_handler(), &set, 0);
                        f != -1) {
                        if (__M_fd.native_handler() == -1) {
                            __M_fd.set_fd(f);
                        }
                    } else {
                        detail::assign_ec(e, errno);
                        __M_fd.close();
                    }
                } else {
                    detail::assign_ec(e, errno);
                }
                return;
            }
            case 0: {
                return;
            }
            case -1: {
                detail::assign_ec(e, errno);
                return;
            }
            }
        } else {
            detail::assign_ec(e, errno);
        }
    }
    void del(int sig) {
        std::error_code e;
        del(sig, e);
        if (e) {
            __CHXNET_THROW_EC(e);
        }
    }

    template <typename CompletionToken>
    decltype(auto) async_wait(CompletionToken&& completion_token) {
        return async_combine<const std::error_code&, int>(
            get_associated_io_context(),
            std::forward<CompletionToken>(completion_token),
            detail::type_identity<operation<>>{}, this);
    }
};
}  // namespace chx::net
