#pragma once

#include "./file_descriptor.hpp"

#include <sys/mman.h>

namespace chx::net {
class mapped_file : CHXNET_NONCOPYABLE {
    void* __M_ptr = nullptr;
    std::size_t __M_sz = 0;

  public:
    using value_type = unsigned char;

    mapped_file() = default;
    mapped_file(mapped_file&& other) noexcept(true)
        : __M_ptr(std::exchange(other.__M_ptr, nullptr)),
          __M_sz(std::exchange(other.__M_sz, 0)) {}
    mapped_file(const file_descriptor& fd, std::size_t file_size,
                int prot = PROT_READ, int flags = MAP_SHARED,
                std::size_t offset = 0) {
        map(fd, file_size, prot, flags, offset);
    }

    ~mapped_file() noexcept(true) {
        std::error_code e;
        unmap(e);
    }

    mapped_file& operator=(mapped_file&& other) noexcept(true) {
        if (this == &other) {
            return *this;
        }
        __M_ptr = std::exchange(other.__M_ptr, nullptr);
        __M_sz = std::exchange(other.__M_sz, 0);
        return *this;
    }

    constexpr unsigned char* data() noexcept(true) {
        return static_cast<unsigned char*>(__M_ptr);
    }
    constexpr std::size_t size() noexcept(true) { return __M_sz; }

    void map(const file_descriptor& fd, std::size_t file_size, int prot,
             int flags, std::size_t offset, std::error_code& e) noexcept(true) {
        unmap(e);
        if (!e) {
            __M_ptr = ::mmap64(nullptr, file_size, prot, flags,
                             fd.native_handler(), offset);
            if (__M_ptr != MAP_FAILED) {
                __M_sz = file_size;
                return;
            } else {
                detail::assign_ec(e, errno);
                __M_sz = 0;
                __M_ptr = nullptr;
            }
        } else {
            return;
        }
    }
    void map(const file_descriptor& fd, std::size_t file_size, int prot,
             int flags, std::size_t offset) {
        std::error_code e;
        map(fd, file_size, prot, flags, offset, e);
        if (e) {
            __CHXNET_THROW_EC(e);
        }
    }

    void unmap(std::error_code& e) noexcept(true) {
        e.clear();
        if (__M_ptr) {
            int r = ::munmap(__M_ptr, __M_sz);
            __M_sz = 0;
            __M_ptr = nullptr;
            if (r == 0) {
                return;
            } else {
                detail::assign_ec(e, errno);
            }
        }
    }
    void unmap() {
        std::error_code e;
        unmap(e);
        if (e) {
            __CHXNET_THROW_EC(e);
        }
    }
};
}  // namespace chx::net
