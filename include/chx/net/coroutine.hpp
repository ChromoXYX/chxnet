#pragma once

#include "attribute.hpp"
#ifdef CHXNET_ENABLE_COROUTINE

#include <coroutine>
#include <tuple>
#include <variant>

#include "async_token.hpp"
#include "detail/type_identity.hpp"
#include "detail/sfinae_placeholder.hpp"

namespace chx::net {
struct this_context_t {
    struct awaitable : std::suspend_never {
        io_context* ctx = nullptr;
        constexpr awaitable(io_context* c) noexcept(true) : ctx(c) {}
        constexpr io_context& await_resume() noexcept(true) { return *ctx; }
    };
};
inline constexpr struct this_context_t this_context = {};

namespace detail::coroutine {
inline void deliver_exception(io_context* ctx, std::exception_ptr ex) {
    ctx->async_nop(
        [ex](const std::error_code& ec) { std::rethrow_exception(ex); });
}

template <typename T = void, bool IsView = false> class task_impl {
    struct promise {
        T __M_v;
        io_context* __M_ctx = nullptr;

        constexpr std::suspend_always initial_suspend() noexcept(true) {
            return {};
        }
        constexpr std::suspend_never final_suspend() noexcept(true) {
            return {};
        }

        constexpr auto await_transform(this_context_t) noexcept(true) {
            return this_context_t::awaitable(__M_ctx);
        }
        template <typename Awaitable>
        constexpr decltype(auto) await_transform(
            Awaitable&& awaitable) noexcept(true) {
            return std::forward<Awaitable>(awaitable);
        }

        template <typename R>
        void return_value(R&& r) noexcept(
            std::is_nothrow_assignable_v<T, decltype(r)>) {
            __M_v = std::forward<R>(r);
        }

        void unhandled_exception() noexcept(true) {
            deliver_exception(__M_ctx, std::current_exception());
        }

        task_impl<T> get_return_object() {
            return {std::coroutine_handle<promise>::from_promise(*this)};
        }

        constexpr void set_io_context(io_context* ctx) noexcept(true) {
            __M_ctx = ctx;
        }
    };

  public:
    using promise_type = promise;

    task_impl(std::coroutine_handle<promise_type> h) noexcept(true)
        : __M_h(h) {}
    ~task_impl() {
        if constexpr (!IsView) {
            if (__M_h) {
                __M_h.destroy();
            }
        }
    }

    void resume() const { __M_h.resume(); }
    constexpr void release() { __M_h = nullptr; }
    constexpr promise_type& promise() noexcept(true) { return __M_h.promise(); }

  protected:
    std::coroutine_handle<promise_type> __M_h;
};

template <bool IsView> class task_impl<void, IsView> {
    struct promise {
        io_context* __M_ctx = nullptr;

        constexpr std::suspend_always initial_suspend() noexcept(true) {
            return {};
        }
        constexpr std::suspend_never final_suspend() noexcept(true) {
            return {};
        }

        constexpr auto await_transform(this_context_t) noexcept(true) {
            return this_context_t::awaitable(__M_ctx);
        }
        template <typename Awaitable>
        constexpr decltype(auto) await_transform(
            Awaitable&& awaitable) noexcept(true) {
            return std::forward<Awaitable>(awaitable);
        }

        constexpr void return_void() noexcept(true) {}

        void unhandled_exception() noexcept(true) {
            deliver_exception(__M_ctx, std::current_exception());
        }

        task_impl<void> get_return_object() {
            return {std::coroutine_handle<promise>::from_promise(*this)};
        }

        constexpr void set_io_context(io_context* ctx) noexcept(true) {
            __M_ctx = ctx;
        }
    };

  public:
    using promise_type = promise;

    constexpr task_impl(std::coroutine_handle<promise_type> h) noexcept(true)
        : __M_h(h) {}
    constexpr explicit task_impl(task_impl&& other) noexcept(true) {
        if constexpr (!IsView) {
            __M_h = std::exchange(other.__M_h, nullptr);
        }
    }
    ~task_impl() {
        if constexpr (!IsView) {
            if (__M_h) {
                __M_h.destroy();
            }
        }
    }

    constexpr task_impl& operator=(task_impl&& other) noexcept(true) {
        if (this == &other) {
            return *this;
        }
        if constexpr (!IsView) {
            __M_h = std::exchange(other.__M_h, nullptr);
        }
        return *this;
    }

    void resume() const { __M_h.resume(); }
    constexpr void release() { __M_h = nullptr; }
    constexpr promise_type& promise() noexcept(true) { return __M_h.promise(); }

  protected:
    std::coroutine_handle<promise_type> __M_h;
};
}  // namespace detail::coroutine

/**
 * @brief Task which owns the handle of a coroutine.
 *
 * @details The ownership of the coroutine handle changes depending on whether
 * the coroutine is suspended or not. If the coroutine is waiting for an async
 * task to complete, the async task will own the coroutine handle. And after
 * await_resume() is called, the task will own the handler. If an exception is
 * thrown due to an error of the async operation, the task still owns the
 * coroutine.
 *
 */
template <typename T = void>
using task = detail::coroutine::task_impl<T, false>;

namespace detail::coroutine {
template <typename T> struct awaitable_impl {
    std::variant<std::monostate, T, std::exception_ptr> __M_v;
    struct guard {
        std::coroutine_handle<> h;

        ~guard() {
            if (h) {
                h.destroy();
            }
        }
    } __M_h;

    constexpr bool await_ready() const noexcept(true) { return false; }
    constexpr void await_suspend(std::coroutine_handle<> h) noexcept(true) {
        __M_h.h = h;
    }
    T await_resume() {
        __M_h.h = nullptr;
        if (__M_v.index() == 2) {
            std::rethrow_exception(std::get<2>(__M_v));
        }
        return std::move(std::get<1>(__M_v));
    }

    void set_value(std::exception_ptr ex) noexcept(true) {
        __M_v.template emplace<2>(ex);
    }
    template <typename... Rs>
    void set_value(Rs&&... rs) noexcept(
        std::is_nothrow_constructible_v<T, decltype(rs)...>) {
        __M_v.template emplace<1>(std::forward<Rs>(rs)...);
    }
    void resume() const noexcept(true) { __M_h.h.resume(); }

    struct view {
        friend awaitable_impl;

      protected:
        constexpr view(awaitable_impl* self) noexcept(true) : __M_impl(self) {}
        awaitable_impl* __M_impl;

      public:
        constexpr bool await_ready() noexcept(true) {
            return __M_impl->await_ready();
        }
        constexpr void await_suspend(std::coroutine_handle<> h) noexcept(true) {
            __M_impl->await_suspend(h);
        }
        constexpr decltype(auto) await_resume() {
            return __M_impl->await_resume();
        }
    };

    constexpr view get_view() noexcept(true) { return this; }
};
}  // namespace detail::coroutine

template <typename T>
using awaitable = typename detail::coroutine::awaitable_impl<T>::view;

namespace detail::coroutine {
template <typename FinalFunctor, typename Token>
struct final_token : FinalFunctor, Token {
    template <typename T>
    final_token(T&& t, detail::type_identity<Token>)
        : FinalFunctor(std::forward<T>(t)), Token() {}

    decltype(auto) operator()(io_context::task_t* task) {
        return FinalFunctor::operator()(static_cast<Token&>(*this), task);
    }
};
template <typename T, typename R>
final_token(T, detail::type_identity<R>)
    -> final_token<std::remove_reference_t<T>, R>;

template <typename...> struct get_tail_type;
template <typename T> struct get_tail_type<T> : detail::type_identity<T> {};
template <typename T, typename... Ts>
struct get_tail_type<T, Ts...>
    : detail::type_identity<typename get_tail_type<Ts...>::type> {};

template <typename T>
constexpr decltype(auto) get_tail_ref(T&& t) noexcept(true) {
    return std::forward<T>(t);
}
template <typename T, typename... Ts>
constexpr decltype(auto) get_tail_ref(T&& t, Ts&&... ts) noexcept(true) {
    return get_tail_ref(std::forward<Ts>(ts)...);
}

template <typename T, typename... Ts>
struct get_head_type : detail::type_identity<T> {};
template <typename T, typename... Ts>
constexpr decltype(auto) get_head_ref(T&& t, Ts&&... ts) noexcept(true) {
    return std::forward<T>(t);
}

template <typename... Ts>
constexpr const std::error_code& get_ec(const std::error_code& ec,
                                        Ts&&...) noexcept(true) {
    return ec;
}

template <typename Awaitable> struct callable_impl {
    Awaitable awaitable;

    template <typename... Ts> void operator()(Ts&&... ts) {
        if constexpr (std::is_same_v<
                          std::decay_t<typename get_head_type<Ts&&...>::type>,
                          std::error_code>) {
            const auto& ref_ec = get_ec(std::forward<Ts>(ts)...);
            if (ref_ec) {
                awaitable.set_value(
                    std::make_exception_ptr(__CHXNET_MAKE_EX(ref_ec)));
            } else {
                awaitable.set_value(get_tail_ref(std::forward<Ts>(ts)...));
            }
        } else {
            awaitable.set_value(std::forward<Ts>(ts)...);
        }
        awaitable.resume();
    }
};

template <typename... Ts> struct ops {
    using awaitable_type =
        awaitable_impl<std::decay_t<typename get_tail_type<Ts...>::type>>;
    using callable_type = callable_impl<awaitable_type>;
    using attribute_type = attribute<async_token>;

    io_context::task_t* __M_task = nullptr;

    template <typename F>
    constexpr decltype(auto) generate_token(io_context::task_t* task,
                                            F&& f) noexcept(true) {
        __M_task = task;
        return final_token(std::forward<F>(f),
                           detail::type_identity<callable_type>());
    }

    template <typename TypeIdentity> constexpr auto get_init(TypeIdentity) {
        return static_cast<callable_type*>(
                   static_cast<typename TypeIdentity::type*>(
                       __M_task->get_underlying_data()))
            ->awaitable.get_view();
    }
};

struct main_op {
    using attribute_type = attribute<async_token>;

    template <typename... Signature>
    constexpr auto bind(
        sfinae_placeholder<std::enable_if_t<(sizeof...(Signature) > 0)>> _ =
            detail::sfinae) const noexcept(true) {
        return ops<Signature...>{};
    }
};
}  // namespace detail::coroutine

/**
 * @brief Helper class to generate a coroutine-based completion token.
 *
 */
using use_coro_t = detail::coroutine::main_op;
inline static constexpr use_coro_t use_coro = {};

/**
 * @brief Spawn a task in io_context.
 *
 * @param ctx The io_context object to spawn task in.
 */
template <typename T> void co_spawn(io_context& ctx, task<T>&& t) {
    t.promise().set_io_context(&ctx);
    ctx.async_nop(
        [t = task<T>(std::move(t))](const std::error_code& ec) mutable {
            if (!ec) {
                t.resume();
                t.release();
            }
        });
}
}  // namespace chx::net

#endif
