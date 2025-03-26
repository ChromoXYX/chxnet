#pragma once

#include <memory>

namespace chx::net::detail {
template <typename T, typename D = std::default_delete<T>>
struct unique_ptr_std_layout : D {
    using pointer = T*;
    using element_type = T;
    using deleter_type = D;

    pointer __M_ptr = nullptr;

    constexpr unique_ptr_std_layout() = default;
    template <typename _T, typename _D>
    unique_ptr_std_layout(const unique_ptr_std_layout<_T, _D>&) = delete;
    template <typename _T, typename _D>
    constexpr unique_ptr_std_layout(
        unique_ptr_std_layout<_T, _D>&&
            other) noexcept(std::is_nothrow_constructible_v<D, _D&&>)
        : D(std::move(other)), __M_ptr(other.release()) {}

    template <typename _T, typename _D>
    constexpr unique_ptr_std_layout(std::unique_ptr<_T, _D>&& other) noexcept(
        std::is_nothrow_constructible_v<D, _D&&>)
        : D(std::move(other.get_deleter())), __M_ptr(other.release()) {}

    template <typename _T, typename _D>
    constexpr unique_ptr_std_layout&
    operator=(unique_ptr_std_layout<_T, _D>&& other) noexcept(
        std::is_nothrow_assignable_v<D, _D&&>) {
        if (this == &other) {
            return *this;
        }
        D::operator=(std::move(other));
        __M_ptr = other.release();
        return *this;
    }

    template <typename _T, typename _D>
    constexpr unique_ptr_std_layout&
    operator=(std::unique_ptr<_T, _D>&& other) noexcept(
        std::is_nothrow_assignable_v<D, _D&&>) {
        D::operator=(std::move(other.get_deleter()));
        __M_ptr = other.release();
        return *this;
    }

    ~unique_ptr_std_layout() {
        if (*this) {
            get_deleter()(get());
        }
    }

    constexpr pointer get() const noexcept(true) {
        return const_cast<pointer>(__M_ptr);
    }
    constexpr pointer operator->() const noexcept(true) { return get(); }
    constexpr T& operator*() const noexcept(true) { return *get(); }
    constexpr operator bool() const noexcept(true) {
        return __M_ptr != nullptr;
    }
    [[nodiscard]] constexpr pointer release() noexcept(true) {
        pointer r = __M_ptr;
        __M_ptr = nullptr;
        return r;
    }

    void reset(pointer p = nullptr) {
        if (*this) {
            get_deleter()(get());
        }
        __M_ptr = p;
    }

    constexpr deleter_type& get_deleter() noexcept(true) { return *this; }
    constexpr const deleter_type& get_deleter() const noexcept(true) {
        return *this;
    }

    // mask deleter
    template <typename... Args> void operator()(Args&&...) = delete;
};
}  // namespace chx::net::detail
