#pragma once

/*
provide reference count for variables that not allocated on heap individually
so owner_guard and enable_weak_from_this is noncopyable
*/

#include <cassert>
#include <cstddef>
#include <cstdio>

#include "./noncopyable.hpp"

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
        constexpr __guard_base(__guard_base&& other) noexcept(true) {
            block = other.block;
            other.block = nullptr;
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
        constexpr __guard_base& operator=(__guard_base&& other) noexcept(true) {
            if (this == &other) {
                return *this;
            }
            block = other.block;
            other.block = nullptr;
            return *this;
        }
        constexpr ~__guard_base() noexcept(true) { release(); }

        constexpr bool is_valid() const noexcept(true) {
            return block != nullptr && block->is_valid();
        }

        constexpr void release() noexcept(true) {
            if (block) {
                (block->*ExitFn)();
                block = nullptr;
            }
        }

      protected:
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
        CHXNET_NONCOPYABLE
        using __guard_base::__guard_base;

        template <typename Object> friend struct enable_weak_from_this;
    };
    struct weak_guard
        : __guard_base<&counter_block::weak_inc, &counter_block::weak_exit> {
        using __guard_base::__guard_base;

        constexpr weak_guard() noexcept(true) : __guard_base(nullptr) {}
        constexpr weak_guard(const weak_guard& other) noexcept(true)
            : __guard_base(other.block) {}

        constexpr weak_guard(const owner_guard& owner) noexcept(true)
            : __guard_base(owner.block) {}

        constexpr weak_guard& operator=(weak_guard&& other) = default;
        constexpr weak_guard& operator=(const weak_guard& other) = default;
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
    friend struct enable_weak_from_this<Object>;

    Object* __M_ptr = nullptr;
    weak_guard __M_guard;

  public:
    constexpr weak_ptr() = default;
    constexpr weak_ptr(const weak_ptr&) = default;

    constexpr weak_ptr& operator=(const weak_ptr&) = default;
    constexpr weak_ptr& operator=(weak_ptr&&) = default;

    constexpr Object* operator->() const noexcept(true) { return __M_ptr; }
    constexpr Object* get() const noexcept(true) { return __M_ptr; }
    constexpr Object& operator*() const noexcept(true) { return *__M_ptr; }

    constexpr operator bool() const noexcept(true) { return !expired(); }

    constexpr bool expired() const noexcept(true) {
        return !__M_guard.is_valid();
    }
    constexpr void release() noexcept(true) {
        __M_guard.release();
        __M_ptr = nullptr;
    }

  private:
    constexpr weak_ptr(Object* obj, const owner_guard& owner) noexcept(true)
        : __M_ptr(obj), __M_guard(owner) {}
};

template <typename Object> struct enable_weak_from_this {
    CHXNET_NONCOPYABLE

    enable_weak_from_this() : owner(new counter_block) {}

    constexpr weak_ptr<Object> weak_from_this() noexcept(true) {
        return weak_ptr(static_cast<Object*>(this), owner);
    }

  protected:
    owner_guard owner;

    constexpr void release() noexcept(true) { owner.release(); }
};
}  // namespace chx::net::detail
