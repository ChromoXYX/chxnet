#pragma once

#include "./detail/noncopyable.hpp"
#include "./error_code.hpp"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

// TODO: file looks so ugly, need better implement

namespace chx::net {
namespace detail {
template <bool IsView> class file_impl : CHXNET_NONCOPYABLE {
    int __M_fd = -1;

  public:
    file_impl() = default;
    constexpr file_impl(file_impl&& other) noexcept(true) {
        __M_fd = other.__M_fd;
        other.__M_fd = -1;
    }
    constexpr file_impl(int fd) noexcept(true) : __M_fd(fd) {}

    ~file_impl() noexcept(true) {
        if constexpr (!IsView) {
            if (__M_fd != -1) {
                ::close(__M_fd);
            }
        }
    }

    constexpr int native_handler() const noexcept(true) { return __M_fd; }
    bool is_open() const noexcept(true) {
        return native_handler() != -1 &&
               (::fcntl(native_handler(), F_GETFD) || errno != EBADF);
    }
    constexpr int release() noexcept(true) {
        int r = __M_fd;
        __M_fd = -1;
        return r;
    }

    void close() {
        std::error_code ec;
        close(ec);
        if (ec) {
            __CHXNET_THROW_EC(ec);
        }
    }
    void close(std::error_code& ec) noexcept(true) {
        if (::close(__M_fd) == -1) {
            net::detail::assign_ec(ec, errno);
        } else {
            ec.clear();
        }
        __M_fd = -1;
    }
};
}  // namespace detail

using file_view = detail::file_impl<true>;
struct file : detail::file_impl<false> {
    file_view view() const noexcept(true) { return {native_handler()}; }
};

inline file make_file(const char* filename, const char* mode,
                      std::error_code& ec) noexcept(true) {
    std::FILE* _f = ::fopen(filename, mode);
    if (_f) {
        int _r = ::fileno(_f);
        if (_r != -1) {
            ec.clear();
            return {_r};
        } else {
            detail::assign_ec(ec, errno);
            return {};
        }
    } else {
        detail::assign_ec(ec, errno);
        return {};
    }
}
inline file make_file(const char* filename, const char* mode) {
    std::error_code ec;
    file f = make_file(filename, mode, ec);
    if (ec) {
        __CHXNET_THROW_EC(ec);
    } else {
        return std::move(f);
    }
}
inline file make_file(const char* filename, int flags,
                      std::error_code& ec) noexcept(true) {
    int _r = ::open(filename, flags);
    if (_r != -1) {
        ec.clear();
        return {_r};
    } else {
        detail::assign_ec(ec, errno);
        return {};
    }
}
inline file make_file(const char* filename, int flags) {
    std::error_code ec;
    file f = make_file(filename, flags, ec);
    if (ec) {
        __CHXNET_THROW_EC(ec);
    } else {
        return std::move(f);
    }
}
}  // namespace chx::net
