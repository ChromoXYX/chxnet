#pragma once

#ifdef CHXNET_ENABLE_COROUTINE

// #ifndef CHXNET_ENABLE_CORO_WHEN_ANY
// #define CHXNET_ENABLE_CORO_WHEN_ANY 0
// #endif

#include "attribute.hpp"

#include <coroutine>
#include <tuple>
#include <variant>

#include "./async_token.hpp"
#include "./detail/type_identity.hpp"
#include "./detail/sfinae_placeholder.hpp"
#include "./cancellation.hpp"
#include "./async_combine.hpp"

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

// struct coro_then_base {
//     virtual void f() = 0;
//     virtual ~coro_then_base() = default;
// };
class task_impl {
    struct promise {
        ~promise() {
            if (__M_then)
                __M_then(__M_then_data);
        }
        // std::unique_ptr<coro_then_base> __M_then;
        void* __M_then_data = nullptr;
        void (*__M_then)(void*) = nullptr;
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
        constexpr decltype(auto) await_transform(Awaitable&& awaitable) {
            return std::forward<Awaitable>(awaitable);
        }

        constexpr void return_void() noexcept(true) {}

        void unhandled_exception() noexcept(true) {
            deliver_exception(__M_ctx, std::current_exception());
        }

        task_impl get_return_object() {
            return {std::coroutine_handle<promise>::from_promise(*this)};
        }

        constexpr void set_io_context(io_context* ctx) noexcept(true) {
            __M_ctx = ctx;
        }
        constexpr io_context& get_associated_io_context() noexcept(true) {
            return *__M_ctx;
        }
    };

  public:
    using promise_type = promise;

    constexpr task_impl(std::coroutine_handle<promise_type> h) noexcept(true)
        : __M_h(h) {}
    constexpr explicit task_impl(task_impl&& other) noexcept(true) {
        __M_h = std::exchange(other.__M_h, nullptr);
    }
    ~task_impl() {
        if (__M_h) {
            __M_h.destroy();
        }
    }

    constexpr task_impl& operator=(task_impl&& other) noexcept(true) {
        if (this == &other) {
            return *this;
        }
        __M_h = std::exchange(other.__M_h, __M_h);
        return *this;
    }

    void resume() const { __M_h.resume(); }
    void release() { __M_h = nullptr; }
    bool done() const noexcept(true) { return __M_h.done(); }
    promise_type& promise() noexcept(true) { return __M_h.promise(); }
    std::coroutine_handle<promise_type> get_handle() noexcept(true) {
        return __M_h;
    }
    io_context& get_associated_io_context() noexcept(true) {
        return promise().get_associated_io_context();
    }

  protected:
    std::coroutine_handle<promise_type> __M_h;
};
}  // namespace detail::coroutine
using task = detail::coroutine::task_impl;

namespace detail::coroutine {
struct awaitable_then_base {
    virtual void reach() = 0;
    virtual ~awaitable_then_base() = default;
};

template <typename T> struct awaitable_impl : CHXNET_NONCOPYABLE {
    using value_type = T;

    struct view : CHXNET_NONCOPYABLE {
        awaitable_impl* pimpl = nullptr;
        std::coroutine_handle<> h = {};

        io_context::task_t* task = nullptr;
        //
        std::unique_ptr<awaitable_then_base> pthen;
        //
        constexpr view(io_context::task_t* t) noexcept(true) : task(t) {}
        view(view&& other)
            : pimpl(std::exchange(other.pimpl, nullptr)),
              h(std::exchange(other.h, {})),
              task(std::exchange(other.task, nullptr)),
              pthen(std::move(other.pthen)) {
            if (pimpl) {
                pimpl->__M_view = this;
            }
        }
        ~view() {
            if (pimpl) {
                pimpl->__M_view = nullptr;
            }
        }

        awaitable_impl create_impl() { return {this}; }
        void resume_h() {
            std::coroutine_handle<> old_h = h;
            std::unique_ptr<awaitable_then_base> old_then(std::move(pthen));
            if (pimpl) {
                // how could pimpl be nullptr while then or h valid?
                pimpl->disconnect();
            }
            if (old_then) {
                old_then->reach();
            } else if (old_h) {
                old_h.resume();
            }
        }

        void set_value(const std::error_code& ec) noexcept(true) {
            if (pimpl) {
                pimpl->__M_v.template emplace<2>(ec);
            }
        }
        template <typename... Rs>
        void set_value(Rs&&... rs) noexcept(
            std::is_nothrow_constructible_v<T, decltype(rs)...>) {
            if (pimpl) {
                pimpl->__M_v.template emplace<1>(std::forward<Rs>(rs)...);
            }
        }
        constexpr io_context& get_associated_io_context() noexcept(true) {
            return task->get_associated_io_context();
        }
    };

    awaitable_impl(view* v) : __M_view(v) { __M_view->pimpl = this; }
    awaitable_impl(awaitable_impl&& other)
        : __M_view(std::exchange(other.__M_view, nullptr)),
          __M_v(std::move(other.__M_v)) {
        assert(__M_view);
        __M_view->pimpl = this;
    }
    ~awaitable_impl() { disconnect(); }

    struct awaitable {
        awaitable_impl& pimpl;

        constexpr bool await_ready() noexcept(true) { return pimpl.ready(); }
        constexpr void await_suspend(std::coroutine_handle<> h) noexcept(true) {
            return pimpl.suspend(h);
        }
        T await_resume() { return pimpl.resume(); }
    };
    friend struct awaitable;
    friend struct view;
    //
    friend struct when_any_impl;
    //

    auto operator co_await() noexcept(true) { return awaitable{*this}; }
    auto get_await() noexcept(true) { return awaitable{*this}; }

    constexpr io_context& get_associated_io_context() noexcept(true) {
        return __M_view->get_associated_io_context();
    }
    cancellation_signal get_cancellation_signal() {
        cancellation_signal s;
        detail::cancellation_assign()(get_associated_task(), s);
        return std::move(s);
    }

    constexpr bool connected() const noexcept(true) { return __M_view; }
    constexpr void disconnect() noexcept(true) {
        if (connected()) {
            __M_view->pimpl = nullptr;
            __M_view->pthen = nullptr;
            __M_view->h = {};
            __M_view->pthen.reset();
            __M_view = nullptr;
        }
    }

  protected:
    view* __M_view = nullptr;
    std::variant<std::monostate, T, std::error_code> __M_v;

    constexpr bool ready() noexcept(true) { return __M_v.index() != 0; }
    constexpr void suspend(std::coroutine_handle<> h) noexcept(true) {
        assert(__M_view);
        __M_view->h = h;
    }
    T resume() {
        if (__M_view) {
            __M_view->h = {};
        }
        if (__M_v.index() == 2) {
            __CHXNET_THROW_EC(std::get<2>(__M_v));
        }
        return std::move(std::get<1>(__M_v));
    }

    constexpr io_context::task_t* get_associated_task() noexcept(true) {
        return __M_view->task;
    }
};

struct when_any_impl {
    template <typename T>
    using extract_value_type = typename std::remove_reference_t<T>::value_type;

    template <typename... Awaitables> struct await_collection {
        template <typename... Ts>
        await_collection(Ts&&... ts) : await_tp(std::forward<Ts>(ts)...) {
            before();
        }

        auto operator co_await() {
            struct awaitable {
                await_collection* self;

                constexpr bool await_ready() noexcept(true) {
                    return self->first_idx != 0;
                }
                constexpr void
                await_suspend(std::coroutine_handle<> h) noexcept(true) {
                    self->handle = h;
                }
                auto await_resume() {
                    struct content {
                        content(
                            std::variant<std::error_code,
                                         extract_value_type<Awaitables>...>&& v,
                            std::size_t i)
                            : val(std::move(v)), index(i) {}
                        std::variant<std::error_code,
                                     extract_value_type<Awaitables>...>
                            val;
                        std::size_t index;
                    };
                    return content(std::move(self->val), self->first_idx);
                }
            };
            return awaitable{this};
        }

        std::variant<std::error_code, extract_value_type<Awaitables>...> val;
        std::size_t first_idx = 0;
        std::tuple<Awaitables...> await_tp;
        std::array<cancellation_signal, sizeof...(Awaitables)> can;
        std::coroutine_handle<> handle;

        template <std::size_t TpIdx> struct then_impl : awaitable_then_base {
            await_collection* self;

            then_impl(await_collection* s) noexcept(true) : self(s) {}

            template <std::size_t Idx> void exclude() {
                if constexpr (Idx < sizeof...(Awaitables)) {
                    if constexpr (Idx != TpIdx) {
                        self->can[Idx].emit();
                        auto& target_tp = std::get<Idx>(self->await_tp);
                        target_tp.disconnect();
                    }
                    exclude<Idx + 1>();
                }
            }

            void reach() override {
                self->first_idx = TpIdx + 1;
                exclude<0>();
                auto& target = std::get<TpIdx>(self->await_tp);
                if (target.__M_v.index() == 1) {
                    self->val.template emplace<TpIdx + 1>(
                        std::move(std::get<1>(target.__M_v)));
                } else {
                    self->val.template emplace<0>(
                        std::move(std::get<2>(target.__M_v)));
                }
                if (self->handle) {
                    self->handle.resume();
                }
            }
        };

        template <std::size_t Idx> void prep() {
            if constexpr (Idx != sizeof...(Awaitables)) {
                auto& a = std::get<Idx>(await_tp);
                if (a.connected()) {
                    can[Idx] = a.get_cancellation_signal();
                } else if (a.ready() && first_idx == 0) {
                    // only cares about 1st awaitable
                    first_idx = Idx + 1;
                    if (a.__M_v.index() == 1) {
                        val.template emplace<Idx + 1>(
                            std::move(std::get<1>(a.__M_v)));
                    } else {
                        val.template emplace<0>(std::get<2>(a.__M_v));
                    }
                }
                prep<Idx + 1>();
            }
        }

        template <std::size_t Idx> void assign() {
            if constexpr (Idx != sizeof...(Awaitables)) {
                auto& target = std::get<Idx>(await_tp);
                if (target.connected()) {
                    target.__M_view->pthen.reset(new then_impl<Idx>(this));
                }
                assign<Idx + 1>();
            }
        }

        template <std::size_t Idx> void disconnect_all() {
            if constexpr (Idx != sizeof...(Awaitables)) {
                auto& target = std::get<Idx>(await_tp);
                if (target.connected()) {
                    target.disconnect();
                }
            }
        }

        void before() {
            prep<0>();
            if (first_idx == 0) {
                // nothing is ready now
                assign<0>();
            } else {
                // we already have one
                for (auto& i : can) {
                    i.emit();
                }
                disconnect_all<0>();
            }
        }
    };
    template <typename... Awaitables>
    await_collection(Awaitables&&...) -> await_collection<
        std::conditional_t<std::is_lvalue_reference_v<Awaitables>, Awaitables&&,
                           std::remove_reference_t<Awaitables>>...>;
};
}  // namespace detail::coroutine

template <typename T>
using awaitable = typename detail::coroutine::awaitable_impl<T>;

namespace detail::coroutine {
template <typename FinalFunctor, typename Token>
struct final_token : FinalFunctor, Token {
    template <typename FF, typename T>
    final_token(FF&& ff, T&& t)
        : FinalFunctor(std::forward<FF>(ff)), Token(std::forward<T>(t)) {}

    decltype(auto) operator()(io_context::task_t* task) {
        return FinalFunctor::operator()(static_cast<Token&>(*this), task);
    }
};
template <typename T, typename R>
final_token(T, R)
    -> final_token<std::remove_reference_t<T>, std::remove_reference_t<R>>;

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

template <typename AwaitableView> struct callable_impl {
    AwaitableView awaitable_view;

    constexpr callable_impl(io_context::task_t* t) noexcept(true)
        : awaitable_view(t) {}
    callable_impl(callable_impl&&) = default;

    template <typename... Ts> void operator()(Ts&&... ts) {
        if constexpr (std::is_same_v<
                          std::decay_t<typename get_head_type<Ts&&...>::type>,
                          std::error_code>) {
            const auto& ref_ec = get_ec(std::forward<Ts>(ts)...);
            if (ref_ec) {
                awaitable_view.set_value(ref_ec);
            } else {
                awaitable_view.set_value(get_tail_ref(std::forward<Ts>(ts)...));
            }
        } else {
            awaitable_view.set_value(std::forward<Ts>(ts)...);
        }
        awaitable_view.resume_h();
    }
};

template <typename... Ts> struct ops {
    using awaitable_view_type = typename awaitable_impl<
        std::decay_t<typename get_tail_type<Ts...>::type>>::view;
    using callable_type = callable_impl<awaitable_view_type>;
    using attribute_type = attribute<async_token>;

    io_context::task_t* __M_task = nullptr;

    template <typename F>
    constexpr decltype(auto) generate_token(io_context::task_t* task,
                                            F&& f) noexcept(true) {
        __M_task = task;
        return final_token(std::forward<F>(f), callable_type(task));
    }

    template <typename TypeIdentity> constexpr auto get_init(TypeIdentity) {
        return static_cast<callable_type*>(
                   static_cast<typename TypeIdentity::type*>(
                       __M_task->get_underlying_data()))
            ->awaitable_view.create_impl();
    }
};

struct main_op {
    using attribute_type = attribute<async_token>;

    template <typename... Signature>
    constexpr auto
    bind(sfinae_placeholder<std::enable_if_t<(sizeof...(Signature) > 0)>> _ =
             detail::sfinae) const noexcept(true) {
        return ops<Signature...>{};
    }
};

template <typename Task, typename CntlType = int> struct co_spawn_operation {
    template <typename T> using rebind = co_spawn_operation<Task, T>;
    Task task;

    template <typename T>
    co_spawn_operation(T&& t) : task(std::forward<T>(t)) {}

    void operator()(CntlType& cntl) {
        task.promise().__M_then_data = this;
        task.promise().__M_then = [](void* p) {
            auto* self = static_cast<co_spawn_operation*>(p);
            (*self)(static_cast<CntlType&>(*self), std::error_code{});
        };
        task.resume();
    }

    void operator()(CntlType& cntl, const std::error_code& e) {
        task.release();
        cntl.complete(e);
    }

    ~co_spawn_operation() {
        // if coro is still suspend, release __M_then, because we are going to
        // destroy it.
        if (task.get_handle()) {
            task.promise().__M_then = nullptr;
        }
    }
};
template <typename Task>
co_spawn_operation(Task&&) -> co_spawn_operation<std::remove_reference_t<Task>>;
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
template <typename Task, typename CompletionToken>
decltype(auto) co_spawn(io_context& ctx, Task&& t,
                        CompletionToken&& completion_token) {
    // return detail::async_operation<detail::tags::coro_cospawn>()(
    //     &ctx, std::move(t),
    //     detail::async_token_bind<const std::error_code&>(
    //         std::forward<CompletionToken>(completion_token)));
    using operation_type =
        decltype(detail::coroutine::co_spawn_operation(std::forward<Task>(t)));
    t.promise().set_io_context(&ctx);
    return async_combine<const std::error_code&>(
        ctx, std::forward<CompletionToken>(completion_token),
        detail::type_identity<operation_type>{}, std::forward<Task>(t));
}

template <typename... Awaitables>
decltype(auto) when_any(Awaitables&&... awaitables) {
    return detail::coroutine::when_any_impl::await_collection(
        std::forward<Awaitables>(awaitables)...);
}
}  // namespace chx::net

#endif
