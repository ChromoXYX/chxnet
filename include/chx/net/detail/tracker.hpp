#pragma once

/*
provide reference count for variables that not allocated on heap individually
so owner_guard and enable_weak_from_this is noncopyable
*/

#include <cassert>
#include <cstddef>
#include <cstdio>
#include <utility>

namespace chx::net::detail {
struct counter_block {
  private:
    template <auto IncFn, auto ExitFn> struct __guard_base {
        friend counter_block;

        constexpr __guard_base(const __guard_base& other) noexcept(true)
            : block(other.block) {
            if (block) {
                (block->*IncFn)();
            }
        }
        constexpr __guard_base&
        operator=(const __guard_base& other) noexcept(true) {
            if (this == &other) {
                return *this;
            }
            if (block) {
                (block->*ExitFn)();
            }
            block = other.block;
            if (block) {
                (block->*IncFn)();
            }
            return *this;
        }
        ~__guard_base() noexcept(true) { release(); }

        constexpr bool is_valid() const noexcept(true) {
            return block != nullptr && block->is_valid();
        }

        constexpr void release() noexcept(true) {
            if (block) {
                (block->*ExitFn)();
                block = nullptr;
            }
        }

        constexpr __guard_base(counter_block* b) noexcept(true) : block(b) {
            if (block) {
                (block->*IncFn)();
            }
        }

        counter_block* block = nullptr;
    };

  public:
    std::size_t owner = 0;
    std::size_t weak = 0;

    constexpr void owner_inc() noexcept(true) { ++owner; }
    constexpr void weak_inc() noexcept(true) { ++weak; }

    constexpr bool is_valid() const noexcept(true) { return owner > 0; }

    constexpr void owner_exit() noexcept(true) {
        owner_dec();
        if (owner == 0 && weak == 0) {
            delete this;
        }
    }
    constexpr void weak_exit() noexcept(true) {
        weak_dec();
        if (owner == 0 && weak == 0) {
            delete this;
        }
    }

    struct owner_guard
        : __guard_base<&counter_block::owner_inc, &counter_block::owner_exit> {
        template <typename Object> friend struct enable_weak_from_this;
        owner_guard() : __guard_base(new counter_block) {}
        owner_guard(const owner_guard&) noexcept(true) = default;
        owner_guard& operator=(const owner_guard&) noexcept(true) = default;

        void renew() { __guard_base::operator=(new counter_block); }
    };
    struct weak_guard
        : __guard_base<&counter_block::weak_inc, &counter_block::weak_exit> {
        constexpr weak_guard() noexcept(true) : __guard_base(nullptr) {}
        constexpr weak_guard(const weak_guard& other) noexcept(true) = default;
        constexpr weak_guard(const owner_guard& owner) noexcept(true)
            : __guard_base(owner.block) {}
        weak_guard& operator=(const weak_guard& other) = default;
    };

  private:
    constexpr void weak_dec() noexcept(true) {
        assert(weak > 0);
        --weak;
    }
    constexpr void owner_dec() noexcept(true) {
        assert(owner > 0);
        --owner;
    }
};
using owner_guard = counter_block::owner_guard;
using weak_guard = counter_block::weak_guard;

template <typename Object> struct enable_weak_from_this;
template <typename Object> class weak_ptr {
    template <typename U> friend struct weak_ptr;

    Object* __M_ptr = nullptr;
    weak_guard __M_guard;

  public:
    constexpr weak_ptr() = default;
    constexpr weak_ptr(const weak_ptr&) = default;

    template <typename U, typename T>
    constexpr weak_ptr(const weak_ptr<U>& p, T* t)
        : __M_ptr(t), __M_guard(p.__M_guard) {}

    template <typename U>
    constexpr weak_ptr(U* obj, const owner_guard& owner) noexcept(true)
        : __M_ptr(obj), __M_guard(owner) {}

    constexpr weak_ptr& operator=(const weak_ptr&) = default;

    constexpr Object* operator->() const noexcept(true) { return __M_ptr; }
    constexpr Object* get() const noexcept(true) { return __M_ptr; }
    constexpr Object& operator*() const noexcept(true) { return *__M_ptr; }

    template <typename U>
    constexpr operator weak_ptr<U>() const noexcept(true) {
        return weak_ptr<U>(*this, static_cast<U*>(__M_ptr));
    }

    constexpr Object* lock() const noexcept(true) { return __M_ptr; }

    constexpr operator bool() const noexcept(true) { return !expired(); }

    constexpr bool expired() const noexcept(true) {
        return !__M_guard.is_valid();
    }
    constexpr void release() noexcept(true) {
        __M_guard.release();
        __M_ptr = nullptr;
    }
};
template <typename U, typename T>
weak_ptr(const weak_ptr<U>&, T*) -> weak_ptr<T>;

template <> class weak_ptr<void> {
    template <typename U> friend struct weak_ptr;

    weak_guard __M_guard;

  public:
    constexpr weak_ptr() = default;
    constexpr weak_ptr(const weak_ptr&) = default;

    template <typename U>
    constexpr weak_ptr(const weak_ptr<U>& p, void* t)
        : __M_guard(p.__M_guard) {}

    weak_ptr& operator=(const weak_ptr&) = default;

    constexpr operator bool() const noexcept(true) { return !expired(); }

    constexpr bool expired() const noexcept(true) {
        return !__M_guard.is_valid();
    }
    constexpr void release() noexcept(true) { __M_guard.release(); }
};

template <typename Object> struct enable_weak_from_this {
  public:
    constexpr weak_ptr<Object> weak_from_this() noexcept(true) {
        return {static_cast<Object*>(this), owner};
    }

  private:
    owner_guard owner;

  protected:
    void renew() { owner.renew(); }
};

struct anchor {
    anchor(anchor&& other) noexcept(true)
        : __M_other(std::exchange(other.__M_other, nullptr)) {
        if (valid()) {
            __M_other->__M_other = this;
        }
    }
    ~anchor() noexcept(true) {
        if (valid()) {
            __M_other->__M_other = nullptr;
            __M_other = nullptr;
        }
    }

    constexpr anchor& operator=(anchor&& other) noexcept(true) {
        if (this == &other) {
            return *this;
        }
        if (valid()) {
            __M_other->__M_other = nullptr;
        }
        __M_other = std::exchange(other.__M_other, nullptr);
        if (valid()) {
            __M_other->__M_other = this;
        }
        return *this;
    }

    constexpr bool valid() const noexcept(true) { return __M_other; }

    static std::pair<anchor, anchor> create() noexcept(true) {
        anchor a, b;
        a.__M_other = &b;
        b.__M_other = &a;
        return {std::move(a), std::move(b)};
    }

  protected:
    constexpr anchor() = default;
    anchor* __M_other = nullptr;
};
}  // namespace chx::net::detail
