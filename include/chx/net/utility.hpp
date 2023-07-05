#pragma once

#include "./file_descriptor.hpp"

#include <sys/mman.h>

namespace chx::net {
class mapped_memory : CHXNET_NONCOPYABLE {
    void* __M_ptr = nullptr;
    std::size_t __M_sz = 0;

  public:
    mapped_memory() = default;
    mapped_memory(mapped_memory&& other) noexcept(true)
        : __M_ptr(std::exchange(other.__M_ptr, nullptr)),
          __M_sz(std::exchange(other.__M_sz, 0)) {}

    ~mapped_memory() {
        std::error_code e;
        unmap(e);
    }

    using value_type = unsigned char;

    constexpr unsigned char* data() noexcept(true) {
        return static_cast<unsigned char*>(__M_ptr);
    }
    constexpr std::size_t size() noexcept(true) { return __M_sz; }

    void map(std::size_t size, int prot, int flags,
             std::error_code& e) noexcept(true) {
        unmap(e);
        if (e) {
            return;
        }
        auto* p = mmap(nullptr, size, prot, flags, 0, 0);
        if (p != nullptr) {
            __M_ptr = p;
            __M_sz = size;
        } else {
            detail::assign_ec(e, errno);
        }
    }
    void map(const file_descriptor& fd, std::size_t size, int prot, int flags,
             std::error_code& e) noexcept(true) {
        unmap(e);
        if (e) {
            return;
        }
        auto* p = mmap(nullptr, size, prot, flags, fd.native_handler(), 0);
        if (p != nullptr) {
            __M_ptr = p;
            __M_sz = size;
        } else {
            detail::assign_ec(e, errno);
        }
    }
    void map(std::size_t size, int prot, int flags) {
        std::error_code e;
        map(size, prot, flags, e);
        if (e) {
            __CHXNET_THROW_EC(e);
        }
    }
    void map(const file_descriptor& fd, std::size_t size, int prot, int flags) {
        std::error_code e;
        map(fd, size, prot, flags, e);
        if (e) {
            __CHXNET_THROW_EC(e);
        }
    }

    void unmap(std::error_code& e) noexcept(true) {
        e.clear();
        if (__M_ptr) {
            if (munmap(__M_ptr, __M_sz) == -1) {
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

    void sync(int flags, std::error_code& e) noexcept(true) {
        e.clear();
        if (__M_ptr) {
            if (msync(data(), size(), flags) == -1) {
                detail::assign_ec(e, errno);
            }
        }
    }
    void sync(int flags) {
        std::error_code e;
        sync(flags, e);
        if (e) {
            __CHXNET_THROW_EC(e);
        }
    }
};
}  // namespace chx::net
