#pragma once

#include "./file_descriptor.hpp"

#include <filesystem>

namespace chx::net {
class file : public file_descriptor {
    void __openat2(int dirfd, const char* pathname, const struct open_how* how,
                   std::error_code& e) noexcept(true) {
        e.clear();
        long _r = syscall(SYS_openat2, dirfd, pathname, how, sizeof(open_how));
        if (_r != -1) {
            close();
            set_fd(_r);
        } else {
            net::detail::assign_ec(e, errno);
        }
    }

  public:
    using file_descriptor::file_descriptor;
    using file_descriptor::operator=;

    file(io_context& ctx, const char* filename, int flags = O_RDONLY,
         int mode = 0)
        : file_descriptor(ctx) {
        int fd = ::open(filename, flags, mode);
        if (fd > 0) {
            file_descriptor::set_fd(fd);
        } else {
            __CHXNET_THROW(errno);
        }
    }
    file(io_context& ctx, const std::string& str, int flags = O_RDONLY,
         int mode = 0)
        : file(ctx, str.c_str(), flags, mode) {}
    file(io_context& ctx, const std::filesystem::path& path,
         int flags = O_RDONLY, int mode = 0)
        : file(ctx, path.c_str(), flags, mode) {}

    template <typename CompletionToken>
    decltype(auto) async_openat(const file_descriptor& dir,
                                const char* filename, const open_how& h,
                                CompletionToken&& completion_token);
    template <typename CompletionToken>
    decltype(auto) async_openat(const file_descriptor& dir,
                                const char* filename,
                                CompletionToken&& completion_token);
    template <typename CompletionToken>
    decltype(auto) async_openat(const char* filename, const open_how& h,
                                CompletionToken&& completion_token);
    template <typename CompletionToken>
    decltype(auto) async_openat(const char* filename,
                                CompletionToken&& completion_token);

    void openat(const char* filename, std::error_code& e) noexcept(true) {
        struct open_how _h = {};
        __openat2(AT_FDCWD, filename, &_h, e);
    }
    void openat(const char* filename, const open_how& h,
                std::error_code& e) noexcept(true) {
        __openat2(AT_FDCWD, filename, &h, e);
    }
    void openat(const file_descriptor& dir, const char* filename,
                std::error_code& e) noexcept(true) {
        struct open_how _h = {};
        __openat2(dir.native_handler(), filename, &_h, e);
    }
    void openat(const file_descriptor& dir, const char* filename,
                const open_how& h, std::error_code& e) noexcept(true) {
        __openat2(dir.native_handler(), filename, &h, e);
    }

    void openat(const char* filename) {
        std::error_code e;
        openat(filename, e);
        if (e) {
            __CHXNET_THROW_EC(e);
        }
    }
    void openat(const char* filename, const open_how& h) {
        std::error_code e;
        openat(filename, h, e);
        if (e) {
            __CHXNET_THROW_EC(e);
        }
    }
    void openat(const file_descriptor& dir, const char* filename) {
        std::error_code e;
        openat(dir, filename, e);
        if (e) {
            __CHXNET_THROW_EC(e);
        }
    }
    void openat(const file_descriptor& dir, const char* filename,
                const open_how& h) {
        std::error_code e;
        openat(dir, filename, h, e);
        if (e) {
            __CHXNET_THROW_EC(e);
        }
    }
};
}  // namespace chx::net

#include "./impl/file.ipp"
