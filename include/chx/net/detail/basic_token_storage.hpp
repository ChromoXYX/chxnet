#pragma once

#include <cstddef>
#include <cstring>
#include <utility>

#include "../exception.hpp"
#include "./noncopyable.hpp"

#ifndef CHXNET_TOKEN_STORAGE_SHRINK_FACTOR
#define CHXNET_TOKEN_STORAGE_SHRINK_FACTOR 2
#endif

namespace chx::net {
class bad_token_storage_call : public exception {
  public:
    bad_token_storage_call() = default;

    virtual const char* what() const noexcept(true) override {
        return "chx::net::bad_token_storage_call";
    }
};

namespace detail {
struct inplace_t {};
constexpr static inline inplace_t inplace = {};

template <typename T> struct fake_emplace {
    explicit fake_emplace() = default;
    using type = T;
};

template <typename Signature> struct func_traits;
template <typename Ret, typename... Args> struct func_traits<Ret(Args...)> {
    using return_type = Ret;
    using args_type = std::tuple<Args...>;
};

template <typename Signature, std::size_t BufferSize, std::size_t Align>
class basic_token_storage {
    CHXNET_NONCOPYABLE
  public:
    using signature_type = Signature;

    static constexpr std::size_t align = Align;
    static constexpr std::size_t buffer_size = std::max(BufferSize, Align);

  private:
    using __ret_type = typename func_traits<signature_type>::return_type;
    using __args_type = typename func_traits<signature_type>::args_type;

    union {
        alignas(align) unsigned char __M_internal_buf[buffer_size] = {};
        std::size_t __M_last_sz;
    };

    template <typename> struct __base_impl;
    template <typename... _Ts> struct __base_impl<std::tuple<_Ts...>> {
        __base_impl() = default;
        virtual ~__base_impl() noexcept(true) = default;

        virtual __ret_type invoke(_Ts... _ts) = 0;
        virtual void* underlying_data() noexcept(true) = 0;
    };
    template <typename, typename> struct __wrapper_impl;
    template <typename _R, typename... _Ts>
    struct __wrapper_impl<_R, std::tuple<_Ts...>>
        : __base_impl<std::tuple<_Ts...>> {
        static_assert(std::is_nothrow_destructible<_R>::value);

        _R _M_r;

        template <typename... _Args>
        __wrapper_impl(_Args&&... _args)
            : _M_r(std::forward<_Args>(_args)...) {}

        virtual __ret_type invoke(_Ts... _ts) override {
            return _M_r(std::forward<_Ts>(_ts)...);
        }
        virtual void* underlying_data() noexcept(true) override {
            return &_M_r;
        }
    };

    using __base = __base_impl<__args_type>;
    template <typename _R> using __wrapper = __wrapper_impl<_R, __args_type>;

    __base* __M_ptr = nullptr;

    constexpr bool __ptr_in_buf() const noexcept(true) {
        return static_cast<void*>(__M_ptr) == __M_internal_buf;
    }

    void __destroy_and_release() noexcept(true) {
        if (valid()) {
            if (__ptr_in_buf()) {
                std::destroy_at(std::exchange(__M_ptr, nullptr));
            } else {
                std::destroy_at(__M_ptr);
                // Allocator::deallocate(std::exchange(__M_ptr, nullptr));
                ::free(std::exchange(__M_ptr, nullptr));
            }
        }
    }

  public:
    basic_token_storage() = default;
    basic_token_storage(basic_token_storage&& other) = delete;

    template <typename CallableObj,
              typename = std::enable_if_t<!std::is_same_v<
                  std::decay_t<CallableObj>, basic_token_storage>>>
    basic_token_storage(CallableObj&& callable_obj) {
        using __internal_obj_type = std::remove_reference_t<CallableObj>;
        using __w = __wrapper<__internal_obj_type>;
        if constexpr (sizeof(__w) <= buffer_size && alignof(__w) <= align) {
            __M_ptr = new (__M_internal_buf)
                __w(std::forward<CallableObj>(callable_obj));
        } else {
            __M_ptr = new  //(Allocator::allocate(sizeof(__w)))
                (::malloc(sizeof(__w)))
                    __w(std::forward<CallableObj>(callable_obj));
            __M_last_sz = sizeof(__w);
        }
    }

    ~basic_token_storage() noexcept(true) { __destroy_and_release(); }

    template <typename T>
    constexpr auto emplace(fake_emplace<T>) noexcept(true) {
        return fake_emplace<T>{};
    }

    template <typename CallableObj,
              typename = std::enable_if_t<!std::is_same_v<
                  std::decay_t<CallableObj>, basic_token_storage>>>
    auto emplace(CallableObj&& callable_obj) {
        using __no_ref = std::remove_reference_t<CallableObj>;
        using __internal_obj_type =
            std::conditional_t<std::is_function_v<__no_ref>,
                               std::add_pointer_t<__no_ref>, __no_ref>;
        using __w = __wrapper<__internal_obj_type>;

        if constexpr (sizeof(__w) <= buffer_size && alignof(__w) <= align) {
            __destroy_and_release();
            __M_ptr = new (__M_internal_buf)
                __w(std::forward<CallableObj>(callable_obj));
        } else {
            if (valid()) {
                if (__ptr_in_buf() || __M_last_sz < sizeof(__w) ||
                    sizeof(__w) <
                        __M_last_sz / CHXNET_TOKEN_STORAGE_SHRINK_FACTOR) {
                    __destroy_and_release();
                    __M_ptr =
                        static_cast<__base*>(::malloc(sizeof(__w))
                                             // Allocator::allocate(sizeof(__w))
                        );
                    __M_last_sz = sizeof(__w);
                } else {
                    std::destroy_at(__M_ptr);
                }
            } else {
                __M_ptr =
                    static_cast<__base*>(::malloc(sizeof(__w))
                                         // Allocator::allocate(sizeof(__w))
                    );
                __M_last_sz = sizeof(__w);
            }
            ::new (__M_ptr) __w(std::forward<CallableObj>(callable_obj));
        }

        struct __ret_t
            : std::integral_constant<bool, (sizeof(__w) <= buffer_size &&
                                            alignof(__w) <= align)> {
            using type = __internal_obj_type;
        };
        return __ret_t{};
    }

    template <typename T, typename... Args>
    auto emplace(inplace_t, Args&&... args) {
        using __no_ref = std::remove_reference_t<T>;
        using __internal_obj_type =
            std::conditional_t<std::is_function_v<__no_ref>,
                               std::add_pointer_t<__no_ref>, __no_ref>;
        using __w = __wrapper<__internal_obj_type>;

        if constexpr (sizeof(__w) <= buffer_size && alignof(__w) <= align) {
            __destroy_and_release();
            __M_ptr = new (__M_internal_buf) __w(std::forward<Args>(args)...);
        } else {
            if (valid()) {
                if (__ptr_in_buf() || __M_last_sz < sizeof(__w) ||
                    sizeof(__w) <
                        __M_last_sz / CHXNET_TOKEN_STORAGE_SHRINK_FACTOR) {
                    __destroy_and_release();
                    __M_ptr =
                        static_cast<__base*>(::malloc(sizeof(__w))
                                             // Allocator::allocate(sizeof(__w))
                        );
                    __M_last_sz = sizeof(__w);
                } else {
                    std::destroy_at(__M_ptr);
                }
            } else {
                __M_ptr =
                    static_cast<__base*>(::malloc(sizeof(__w))
                                         // Allocator::allocate(sizeof(__w))
                    );
                __M_last_sz = sizeof(__w);
            }
            ::new (__M_ptr) __w(std::forward<Args>(args)...);
        }

        struct __ret_t
            : std::integral_constant<bool, (sizeof(__w) <= buffer_size &&
                                            alignof(__w) <= align)> {
            using type = __internal_obj_type;
        };
        return __ret_t{};
    }

    constexpr bool valid() const noexcept(true) { return __M_ptr; }
    constexpr operator bool() const noexcept { return valid(); }

    void clear() noexcept(true) { __destroy_and_release(); }
    void* underlying_data() const noexcept(true) {
        return __M_ptr->underlying_data();
    }

    template <typename... Args> decltype(auto) operator()(Args&&... args) {
        if (valid()) {
            return __M_ptr->invoke(std::forward<Args>(args)...);
        } else {
            rethrow_with_fatal(
                std::make_exception_ptr(bad_token_storage_call()));
        }
    }
};
}  // namespace detail
}  // namespace chx::net
