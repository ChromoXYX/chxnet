#pragma once

#include "./file_descriptor.hpp"
#include "./detail/remove_rvalue_reference.hpp"

#include <sys/mman.h>

namespace chx::net {
class mapped_file {
    CHXNET_NONCOPYABLE

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

    constexpr unsigned char* data() const noexcept(true) {
        return static_cast<unsigned char*>(__M_ptr);
    }
    constexpr std::size_t size() const noexcept(true) { return __M_sz; }

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
                assign_ec(e, errno);
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
                assign_ec(e, errno);
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

    constexpr mutable_buffer subview(std::size_t pos,
                                     std::size_t len) noexcept(true) {
        return mutable_buffer{data() + pos, len};
    }
    constexpr const_buffer subview(std::size_t pos, std::size_t len) const
        noexcept(true) {
        return const_buffer{data() + pos, len};
    }
};

template <typename F> class ref_fn {
    F& __M_fn;

  public:
    constexpr ref_fn(F& f) noexcept(true) : __M_fn(f) {}

    template <typename... Args>
    decltype(auto) operator()(Args&&... args) noexcept(
        std::is_nothrow_invocable_v<std::decay_t<F>, Args&&...>) {
        return __M_fn(std::forward<Args>(args)...);
    }
};

template <typename F, typename... Args> class fixed_ref_fn {
    F& __M_f;

  public:
    template <template <typename> typename TypeIdentity>
    constexpr fixed_ref_fn(F& f, TypeIdentity<Args>...) noexcept(true)
        : __M_f(f) {}
    constexpr fixed_ref_fn(F& f) noexcept(true) : __M_f(f) {}

    std::invoke_result_t<std::decay_t<F>, Args&&...>
    operator()(Args&&... args) noexcept(
        std::is_nothrow_invocable_v<std::decay_t<F>, Args&&...>) {
        return __M_f(std::forward<Args>(args)...);
    }
};

template <typename Container> class carrier {
    Container __M_c;
    std::size_t __M_offset = 0, __M_len = 0;

  public:
    carrier(Container&& c, std::size_t offset, std::size_t len)
        : __M_c(std::move(c)), __M_offset(offset), __M_len(len) {}
    carrier(carrier&&) = default;
    carrier& operator=(carrier&&) = default;

    constexpr std::size_t size() const noexcept(true) { return __M_len; }
    // constexpr void* data() noexcept(true) {
    //     return static_cast<unsigned char*>(buffer(__M_c).data()) + __M_offset;
    // }
    constexpr const void* data() const noexcept(true) {
        return static_cast<const unsigned char*>(buffer(__M_c).data()) +
               __M_offset;
    }

    constexpr void remove_prefix(std::size_t n) noexcept(true) {
        __M_offset += n;
        __M_len -= n;
    }
    constexpr void remove_suffix(std::size_t n) noexcept(true) { __M_len -= n; }
};

template <typename Container> class offset_carrier {
    Container __M_c;
    std::size_t __M_offset = 0;

  public:
    offset_carrier(Container&& c, std::size_t offset)
        : __M_c(std::move(c)), __M_offset(offset) {}
    offset_carrier(offset_carrier&&) = default;
    offset_carrier& operator=(offset_carrier&&) = default;

    constexpr std::size_t size() const noexcept(true) {
        return buffer(__M_c).size() - __M_offset;
    }
    // constexpr void* data() noexcept(true) {
    //     return static_cast<unsigned char*>(buffer(__M_c).data()) + __M_offset;
    // }
    constexpr const void* data() const noexcept(true) {
        return static_cast<const unsigned char*>(buffer(__M_c).data()) +
               __M_offset;
    }

    constexpr void remove_prefix(std::size_t n) noexcept(true) {
        __M_offset += n;
    }
};

class vcarrier {
    struct __c {
        virtual std::size_t size() const noexcept(true) = 0;
        virtual const void* data() const noexcept(true) = 0;
        virtual ~__c() = default;
    };
    std::unique_ptr<__c> __M_c;

    vcarrier(std::unique_ptr<__c> p) noexcept(true) : __M_c(std::move(p)) {}

  public:
    vcarrier(vcarrier&&) = default;
    vcarrier& operator=(vcarrier&&) = default;

    std::size_t size() const noexcept(true) {
        return __M_c ? __M_c->size() : 0;
    }
    const void* data() const noexcept(true) {
        return __M_c ? __M_c->data() : nullptr;
    }

    template <typename T> static vcarrier create(T&& t) {
        struct impl : __c {
            typename detail::remove_rvalue_reference<T&&>::type r;
            impl(T&& t) : r(std::forward<T>(t)) {}

            std::size_t size() const noexcept(true) override {
                return r.size();
            }
            const void* data() const noexcept(true) { return r.data(); }
        };
        return {std::make_unique<impl>(std::forward<T>(t))};
    }
};
}  // namespace chx::net
