#pragma once

#ifdef CHXNET_ENABLE_COROUTINE

#include "attribute.hpp"

#include <coroutine>
#include <tuple>
#include <variant>

#include "./async_token.hpp"
#include "./detail/type_identity.hpp"
#include "./detail/sfinae_placeholder.hpp"
#include "./cancellation.hpp"

namespace chx::net::detail::tags {
struct coro_cospawn {};
struct coro_when_any_cospawn {};
struct coro_when_any_success_poll {};
struct coro_when_any_release {};
}  // namespace chx::net::detail::tags

template <>
struct chx::net::detail::async_operation<chx::net::detail::tags::coro_cospawn> {
    template <typename Task, typename CompletionToken>
    decltype(auto) operator()(io_context* ctx, Task&& task,
                              CompletionToken&& completion_token);
};

template <>
struct chx::net::detail::async_operation<
    chx::net::detail::tags::coro_when_any_cospawn> {
    template <typename Task, typename Cntl, typename CompletionToken>
    decltype(auto) operator()(io_context* ctx, Task&& task, type_identity<Cntl>,
                              CompletionToken&& completion_token);
};

template <>
struct chx::net::detail::async_operation<
    chx::net::detail::tags::coro_when_any_success_poll> {
    void operator()(io_context::task_t* t) {
        t->__M_res = 0;
        t->__M_ec.clear();
        t->__M_token(t);
    }
};

template <>
struct chx::net::detail::async_operation<
    chx::net::detail::tags::coro_when_any_release> {
    void operator()(io_context::task_t* t) {
        t->get_associated_io_context().release(t);
    }
};

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
struct this_promise_t {};
inline constexpr struct this_promise_t this_promise = {};
struct this_task_t {};
inline constexpr struct this_task_t this_task = {};

inline void deliver_exception(io_context* ctx, std::exception_ptr ex) {
    ctx->async_nop(
        [ex](const std::error_code& ec) { std::rethrow_exception(ex); });
}

template <typename T> class task_impl {
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
        constexpr decltype(auto)
        await_transform(Awaitable&& awaitable) noexcept(true) {
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
        constexpr io_context& get_associated_io_context() noexcept(true) {
            return *__M_ctx;
        }
    };

  public:
    using promise_type = promise;

    task_impl(std::coroutine_handle<promise_type> h) noexcept(true)
        : __M_h(h) {}
    ~task_impl() {
        if (__M_h) {
            __M_h.destroy();
        }
    }

    void resume() const { __M_h.resume(); }
    void release() { __M_h = nullptr; }
    bool done() const noexcept(true) { return __M_h.done(); }
    promise_type& promise() noexcept(true) { return __M_h.promise(); }
    io_context& get_associated_io_context() noexcept(true) {
        return promise().get_associated_io_context();
    }

  protected:
    std::coroutine_handle<promise_type> __M_h;
};
template <> class task_impl<void> {
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
        constexpr decltype(auto)
        await_transform(Awaitable&& awaitable) noexcept(true) {
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
        __M_h = std::exchange(other.__M_h, nullptr);
        return *this;
    }

    void resume() const { __M_h.resume(); }
    void release() { __M_h = nullptr; }
    bool done() const noexcept(true) { return __M_h.done(); }
    promise_type& promise() noexcept(true) { return __M_h.promise(); }
    io_context& get_associated_io_context() noexcept(true) {
        return promise().get_associated_io_context();
    }

  protected:
    std::coroutine_handle<promise_type> __M_h;
};

class task_task {
    struct promise {
        io_context::task_t* __M_task = nullptr;
        void* __M_cntl = nullptr;

        constexpr std::suspend_always initial_suspend() noexcept(true) {
            return {};
        }
        constexpr std::suspend_never final_suspend() noexcept(true) {
            return {};
        }

        constexpr auto await_transform(this_context_t) noexcept(true) {
            return this_context_t::awaitable(
                &__M_task->get_associated_io_context());
        }
        constexpr auto await_transform(this_task_t) noexcept(true) {
            struct awaitable : std::suspend_never {
                io_context::task_t* t;
                constexpr awaitable(io_context::task_t* tt) noexcept(true)
                    : t(tt) {}
                constexpr io_context::task_t* await_resume() noexcept(true) {
                    return t;
                }
            };
            return awaitable{__M_task};
        }
        constexpr auto await_transform(this_promise_t) noexcept(true) {
            struct awaitable : std::suspend_never {
                promise& p;
                constexpr awaitable(promise& pp) noexcept(true) : p(pp) {}
                constexpr promise& await_resume() noexcept(true) { return p; }
            };
            return awaitable(*this);
        }
        template <typename Awaitable>
        constexpr decltype(auto)
        await_transform(Awaitable&& awaitable) noexcept(true) {
            return std::forward<Awaitable>(awaitable);
        }

        constexpr void return_void() noexcept(true) {}

        void unhandled_exception() noexcept(true) {
            deliver_exception(&__M_task->get_associated_io_context(),
                              std::current_exception());
        }

        task_task get_return_object() {
            return {std::coroutine_handle<promise>::from_promise(*this)};
        }

        constexpr void
        set_associated_task(io_context::task_t* t) noexcept(true) {
            __M_task = t;
        }
        constexpr io_context::task_t* get_associated_task() noexcept(true) {
            return __M_task;
        }
    };

  public:
    using promise_type = promise;

    constexpr task_task(std::coroutine_handle<promise_type> h) noexcept(true)
        : __M_h(h) {}
    constexpr explicit task_task(task_task&& other) noexcept(true) {
        __M_h = std::exchange(other.__M_h, nullptr);
    }
    ~task_task() {
        if (__M_h) {
            __M_h.destroy();
        }
    }

    constexpr task_task& operator=(task_task&& other) noexcept(true) {
        if (this == &other) {
            return *this;
        }
        __M_h = std::exchange(other.__M_h, nullptr);
        return *this;
    }

    void resume() const { __M_h.resume(); }
    void release() { __M_h = nullptr; }
    bool done() const noexcept(true) { return __M_h.done(); }
    promise_type& promise() noexcept(true) { return __M_h.promise(); }

  protected:
    std::coroutine_handle<promise_type> __M_h;
};

template <typename T> struct is_task_capture : std::false_type {};
template <> struct is_task_capture<task_task> : std::true_type {};
}  // namespace detail::coroutine

template <typename T = void> using task = detail::coroutine::task_impl<T>;

namespace detail::coroutine {
class otherwise_base {
  public:
    virtual void oper(void*) = 0;
    virtual ~otherwise_base() = default;
};

template <typename T> struct awaitable_impl : CHXNET_NONCOPYABLE {
    struct view : CHXNET_NONCOPYABLE {
        awaitable_impl* pimpl = nullptr;
        std::coroutine_handle<> h = {};

        std::unique_ptr<otherwise_base> otherwise;
        std::unique_ptr<cancellation_base> cancel_op;
        io_context::task_t* task = nullptr;

        constexpr view(io_context::task_t* t) noexcept(true) : task(t) {}
        view(view&& other)
            : pimpl(std::exchange(other.pimpl, nullptr)),
              h(std::exchange(other.h, {})),
              otherwise(std::exchange(other.otherwise, nullptr)),
              task(std::exchange(other.task, nullptr)),
              cancel_op(std::exchange(other.cancel_op, nullptr)) {
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
            if (h) {
                h.resume();
            }
            if (otherwise) {
                otherwise->oper(this);
            }
        }

        void set_value(const std::error_code& ec) noexcept(true) {
            assert(pimpl);
            pimpl->__M_v.template emplace<2>(ec);
        }
        template <typename... Rs>
        void set_value(Rs&&... rs) noexcept(
            std::is_nothrow_constructible_v<T, decltype(rs)...>) {
            assert(pimpl);
            pimpl->__M_v.template emplace<1>(std::forward<Rs>(rs)...);
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
    ~awaitable_impl() {
        if (__M_view) {
            __M_view->pimpl = nullptr;
            __M_view->h = {};
        }
    }

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
    friend struct when_any_impl;

    auto operator co_await() noexcept(true) { return awaitable{*this}; }
    auto get_await() noexcept(true) { return awaitable{*this}; }

    constexpr io_context& get_associated_io_context() noexcept(true) {
        return __M_view->get_associated_io_context();
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

    void poll_resume() noexcept(true) {
        if (__M_view) {
            __M_view->h = {};
        }
    }
    constexpr std::unique_ptr<otherwise_base>& get_otherwise() noexcept(true) {
        return __M_view->otherwise;
    }
    constexpr io_context::task_t* get_associated_task() noexcept(true) {
        return __M_view->task;
    }
    constexpr void
    set_cancellation_method(cancellation_base* b) noexcept(true) {
        __M_view->cancel_op.reset(b);
    }
    cancellation_signal get_cancellation_signal() noexcept(true) {
        cancellation_signal s;
        if (!__M_view->cancel_op) {
            cancellation_assign()(get_associated_task(), s);
        } else {
            struct cancel_view : cancellation_base {
                cancellation_base* ptr;
                cancel_view(cancellation_base* p) noexcept(true) : ptr(p) {}
                void operator()() override { (*ptr)(); }
            };
            cancellation_assign().emplace(
                new cancel_view(__M_view->cancel_op.get()), s);
        }
        return std::move(s);
    }
    constexpr auto get_poll_await() noexcept(true) {
        struct poll_awaitable {
            awaitable_impl& pimpl;
            constexpr bool await_ready() noexcept(true) {
                return pimpl.ready();
            }
            constexpr void
            await_suspend(std::coroutine_handle<> h) noexcept(true) {
                return pimpl.suspend(h);
            }
            void await_resume() noexcept(true) { pimpl.poll_resume(); }
        };

        return poll_awaitable{*this};
    }
};

template <std::size_t... Idx, typename Func, typename Tp>
void when_any_apply(std::integer_sequence<std::size_t, Idx...>, Func&& func,
                    Tp&& tp) {
    func(std::get<Idx>(tp)...);
}

struct when_any_impl {
    template <typename T>
    constexpr auto get_cancellation_signal(awaitable_impl<T>& awaitable) const
        noexcept(true) {
        return awaitable.get_cancellation_signal();
    }

    template <std::size_t Idx, typename Tp> void cancel_all(Tp& tp) const {
        if constexpr (Idx < std::tuple_size_v<Tp>) {
            std::get<Idx>(tp).emit();
            cancel_all<Idx + 1>(tp);
        }
    }

    template <typename... Ts> struct cntl_type {
        std::variant<std::monostate, Ts...> value;
        std::error_code ec;
    };

    template <std::size_t Idx, typename T, typename Tp, typename... Ts>
    void assign(awaitable_impl<T>& awaitable, Tp&& tp,
                cntl_type<Ts...>& val) const noexcept(true) {
        struct otherwise_impl : otherwise_base {
            std::remove_reference_t<Tp> cancellation_tp;
            cntl_type<Ts...>& cntl;

            otherwise_impl(Tp&& tp, cntl_type<Ts...>& val)
                : cancellation_tp(std::forward<Tp>(tp)), cntl(val) {}

            void oper(void* ptr) override {
                using view_type = typename awaitable_impl<T>::view;
                using awaitable = awaitable_impl<T>;
                view_type* view = static_cast<view_type*>(ptr);

                if (cntl.value.index() == 0 || !cntl.ec) {
                    awaitable* await = view->pimpl;
                    if (await->__M_v.index() == 1) {
                        cntl.value.template emplace<Idx + 1>(
                            std::move(std::get<1>(await->__M_v)));
                    } else {
                        cntl.ec = std::get<2>(await->__M_v);
                    }
                    when_any_impl().cancel_all<0>(cancellation_tp);
                }
            }
        };

        if (awaitable.__M_view)
            awaitable.__M_view->otherwise.reset(
                new otherwise_impl(std::forward<Tp>(tp), val));
    }

    template <std::size_t... Idx, typename Tp>
    void when_any_assign_apply(std::integer_sequence<std::size_t, Idx...>,
                               Tp&& tp) {
        (..., (std::get<Idx>(tp).emit()));
    }

    template <std::size_t Idx, typename... Ts, typename Cntl>
    constexpr std::size_t
    when_any_assign_impl(std::tuple<awaitable_impl<Ts>&...>& tp, Cntl& cntl) {
        if constexpr (Idx < sizeof...(Ts)) {
            if (!std::get<Idx>(tp).ready()) {
                assign<Idx>(std::get<Idx>(tp), when_any_without<Idx, 0>(tp),
                            cntl);
                return when_any_assign_impl<Idx + 1>(tp, cntl);
            } else {
                when_any_assign_apply(
                    std::make_integer_sequence<std::size_t,
                                               sizeof...(Ts) - 1>(),
                    when_any_without<Idx, 0>(tp));
                return Idx;
            }
        } else {
            return Idx;
        }
    }

    template <std::size_t Skip, std::size_t Idx, typename... Ts>
    constexpr auto
    when_any_without(std::tuple<awaitable_impl<Ts>&...>& tp) noexcept(true) {
        if constexpr (Idx == sizeof...(Ts)) {
            return std::tuple{};
        } else {
            if constexpr (Skip == Idx) {
                return when_any_without<Skip, Idx + 1>(tp);
            } else {
                if constexpr (Idx < sizeof...(Ts) - 1) {
                    return std::tuple_cat(
                        std::make_tuple(
                            !std::get<Idx>(tp).ready()
                                ? get_cancellation_signal(std::get<Idx>(tp))
                                : cancellation_signal{}),
                        when_any_without<Skip, Idx + 1>(tp));
                } else {
                    return std::make_tuple(
                        !std::get<Idx>(tp).ready()
                            ? get_cancellation_signal(std::get<Idx>(tp))
                            : cancellation_signal{});
                }
            }
        }
    }

    template <std::size_t I, typename... Ts, typename... Rs>
    void select(std::size_t idx, cntl_type<Ts...>& cntl,
                std::tuple<awaitable_impl<Rs>&...> ref) {
        if constexpr (I == sizeof...(Ts)) {
        } else {
            if (idx != I) {
                select<I + 1>(idx, cntl, ref);
            } else {
                auto& ref_a = std::get<I>(ref);
                if (ref_a.__M_v.index() == 1) {
                    cntl.value.template emplace<I + 1>(
                        std::move(std::get<1>(ref_a.__M_v)));
                } else {
                    cntl.ec = std::get<2>(ref_a.__M_v);
                }
            }
        }
    }

    template <typename... Ts>
    auto poll(io_context* ctx, awaitable_impl<Ts>&... ts);
};

template <typename Cntl, typename... Ts>
constexpr std::size_t when_any_assign(Cntl& cntl, awaitable_impl<Ts>&... ts) {
    std::tuple<awaitable_impl<Ts>&...> tp{ts...};
    return when_any_impl().when_any_assign_impl<0>(tp, cntl);
}
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

template <typename Task, typename Cntl, typename CompletionToken>
decltype(auto) when_any_co_spawn(io_context& ctx, Task&& t,
                                 type_identity<Cntl> cntl_t,
                                 CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::coro_when_any_cospawn>()(
        &ctx, std::move(t), cntl_t,
        detail::async_token_bind<const std::error_code&, Cntl>(
            std::forward<CompletionToken>(completion_token)));
}
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
    return detail::async_operation<detail::tags::coro_cospawn>()(
        &ctx, std::move(t),
        detail::async_token_bind<const std::error_code&>(
            std::forward<CompletionToken>(completion_token)));
}

template <typename... Ts>
constexpr decltype(auto) when_any(awaitable<Ts>&... ts) {
    constexpr auto get_first = [](auto& t, auto&... ts) -> decltype(auto) {
        return t;
    };
    return detail::coroutine::when_any_impl().poll(
        &get_first(ts...).get_associated_io_context(), ts...);
}

namespace detail {
template <typename... Ts> struct when_any_operator_impl {
    std::tuple<awaitable<Ts>&...> ref_tp;

    constexpr when_any_operator_impl(awaitable<Ts>&... ts) noexcept(true)
        : ref_tp(ts...) {}

    template <typename T>
    constexpr when_any_operator_impl<awaitable<Ts>&..., awaitable<T>&>
    extend(awaitable<T>& a) noexcept(true) {
        return std::tuple_cat(ref_tp, std::tuple<awaitable<T>&>{a});
    }

    template <std::size_t... Idx>
    constexpr decltype(auto)
    apply_impl(std::integer_sequence<std::size_t, Idx...>) {
        return when_any(std::get<Idx>(ref_tp)...);
    }
    constexpr decltype(auto) operator()() {
        return apply_impl(
            std::make_integer_sequence<std::size_t, sizeof...(Ts)>());
    }
};
}  // namespace detail

template <typename T1, typename T2>
auto operator||(awaitable<T1>& a1, awaitable<T2>& a2) noexcept(true) {
    return detail::when_any_operator_impl(a1, a2);
}
template <typename... Ts, typename T>
constexpr auto operator||(detail::when_any_operator_impl<Ts...>& impl,
                          awaitable<T>& a) noexcept(true) {
    return impl.extend(a);
}
template <typename T, typename... Ts>
constexpr auto
operator||(awaitable<T>& a,
           detail::when_any_operator_impl<Ts...>& impl) noexcept(true) {
    return impl.extend(a);
}
}  // namespace chx::net

template <typename Task, typename CompletionToken>
decltype(auto)
chx::net::detail::async_operation<chx::net::detail::tags::coro_cospawn>::
operator()(io_context* ctx, Task&& coro, CompletionToken&& completion_token) {
    io_context::__task_t* task = ctx->acquire();
    auto* sqe = ctx->get_sqe(task);
    io_uring_prep_nop(sqe);

    coro.promise().set_io_context(ctx);
    return detail::async_token_init(
        task->__M_token.emplace(detail::async_token_generate(
            task,
            [coro = std::remove_reference_t<Task>(std::move(coro))](
                auto& token, io_context::__task_t* self) mutable -> int {
                if (!self->__M_ec) {
                    coro.resume();
                    coro.release();
                }
                token(self->__M_ec);
                return 0;
            },
            std::forward<CompletionToken>(completion_token))),
        std::forward<CompletionToken>(completion_token));
}

template <typename Task, typename Cntl, typename CompletionToken>
decltype(auto) chx::net::detail::
    async_operation<chx::net::detail::tags::coro_when_any_cospawn>::operator()(
        io_context* ctx, Task&& coro, type_identity<Cntl>,
        CompletionToken&& completion_token) {
    io_context::__task_t* task = ctx->acquire();
    auto* sqe = ctx->get_sqe(task);
    io_uring_prep_nop(sqe);

    task->__M_persist = true;
    // if constexpr (coroutine::is_task_capture<std::decay_t<Task>>::value) {
    coro.promise().set_associated_task(task);
    // } else {
    //     coro.promise().set_io_context(ctx);
    // }

    return detail::async_token_init(
        task->__M_token.emplace(detail::async_token_generate(
            task,
            [done = false,
             coro = std::remove_reference_t<Task>(std::move(coro))](
                auto& token, io_context::__task_t* self) mutable -> int {
                if (!done) {
                    coro.resume();
                    done = true;
                } else {
                    self->get_associated_io_context().async_nop(
                        [token = std::move(token),
                         cntl = std::move(
                             *static_cast<Cntl*>(coro.promise().__M_cntl))](
                            const std::error_code& e) mutable {
                            token(e, std::move(cntl));
                        });
                    coro.release();
                }
                return 0;
            },
            std::forward<CompletionToken>(completion_token))),
        std::forward<CompletionToken>(completion_token));
}

template <typename... Ts>
auto chx::net::detail::coroutine::when_any_impl::poll(
    io_context* ctx, awaitable_impl<Ts>&... ts) {
    using cntl_t = when_any_impl::cntl_type<std::decay_t<Ts>...>;
    auto poll_wrapper = [](auto&... ts) -> task_task {
        cntl_t cntl;
        auto& promise = co_await this_promise;
        promise.__M_cntl = &cntl;
        std::tuple<awaitable<Ts>&...> tp{ts...};
        std::size_t idx = when_any_assign(cntl, ts...);
        (..., (co_await ts.get_poll_await()));

        if (idx != sizeof...(ts)) {
            assert(idx >= 0 && idx < sizeof...(ts));
            when_any_impl().template select<0>(
                idx, cntl, std::tuple<awaitable<Ts>&...>{ts...});
        }

        io_context::task_t* task = co_await this_task;
        async_operation<tags::coro_when_any_success_poll>()(task);
        async_operation<tags::coro_when_any_release>()(task);
        co_return;
    };

    auto ret = coroutine::when_any_co_spawn(
        *ctx, poll_wrapper(ts...), type_identity<cntl_t>(), net::use_coro);

    struct cancel_method : cancellation_base {
        using Tp =
            std::tuple<std::decay_t<decltype(ts.get_cancellation_signal())>...>;
        Tp tp;

        cancel_method(decltype(ts.get_cancellation_signal())&&... cs) noexcept(
            true)
            : tp(std::move(cs)...) {}

        void operator()() override {
            when_any_apply(
                std::make_integer_sequence<std::size_t, sizeof...(ts)>(),
                [](auto&... s) { (..., (s.emit())); }, tp);
        }
    };
    ret.set_cancellation_method(
        new cancel_method(ts.get_cancellation_signal()...));
    return std::move(ret);
}

#endif
