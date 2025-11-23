#pragma once

#include "./io_context.hpp"
#include "./async_token.hpp"
#include "./attribute.hpp"
#include "./detail/task_aware.hpp"
#include "./detail/type_identity.hpp"
#include "./detail/deliver_exception.hpp"

#include <algorithm>

namespace chx::net {
namespace detail {
struct async_combine_no_init_param {};

namespace tags {
struct async_combine_persist {};
struct async_combine_use_delivery {};
}  // namespace tags
template <> struct async_operation<tags::async_combine_persist> {
    void operator()(io_context::task_t* task) noexcept(true) {
        task->get_associated_io_context().release(task);
    }
};

template <> struct async_operation<tags::async_combine_use_delivery> {
    template <typename FinalFunctor, typename CompletionToken>
    decltype(auto) operator()(io_context* ctx, FinalFunctor&& final_functor,
                              CompletionToken&& completion_token) {
        return ctx->async_delivery<>(
            std::forward<FinalFunctor>(final_functor),
            std::forward<CompletionToken>(completion_token));
    }
};

template <typename Operation, typename CompletionToken,
          typename EnableReferenceCount>
struct async_combine_impl
    : Operation::template rebind<
          async_combine_impl<Operation, CompletionToken, EnableReferenceCount>>,
      CompletionToken {
    CHXNET_NONCOPYABLE

    using attribute_type = attribute<async_token>;
    using rebind_operation =
        typename Operation::template rebind<async_combine_impl>;

    io_context::task_t* const __M_associated_task;
    std::vector<io_context::task_t*> __M_subtasks;

    template <bool E, typename C, typename OpType, typename... OpArgs,
              std::size_t... OpArgsI, typename InitParam>
    constexpr async_combine_impl(std::integral_constant<bool, E>,
                                 io_context::task_t* task, C&& c,
                                 type_identity<OpType>,
                                 std::tuple<OpArgs...> args,
                                 std::integer_sequence<std::size_t, OpArgsI...>,
                                 InitParam init_param)
        : __M_associated_task(task),
          rebind_operation(std::get<OpArgsI>(std::move(args))...),
          CompletionToken(std::forward<C>(c)) {
        if constexpr (std::is_same_v<InitParam, async_combine_no_init_param>) {
            async_operation<tags::async_combine_use_delivery>()(
                &get_associated_io_context(),
                [](auto& token, io_context::task_t* self) mutable -> int {
                    token();
                    return 0;
                },
                next());
        } else {
            async_operation<tags::async_combine_use_delivery>()(
                &get_associated_io_context(),
                [init_param = std::move(init_param)](
                    auto& token, io_context::task_t* self) mutable -> int {
                    token(std::move(init_param));
                    return 0;
                },
                next());
        }
    }

    ~async_combine_impl() {}

    int operator()(io_context::task_t*);

    constexpr io_context& get_associated_io_context() noexcept(true) {
        return get_associated_task()->get_associated_io_context();
    }
    constexpr io_context::task_t* get_associated_task() noexcept(true) {
        return __M_associated_task;
    }
    constexpr CompletionToken& get_completion_token() noexcept(true) {
        return *this;
    }
    // this should be the last fn call of this object.
    // could assume complete() may only throw fatal_exception.
    template <typename... Ts> decltype(auto) complete(Ts&&... ts) {
        try {
            if constexpr (!EnableReferenceCount::value) {
                assert(__M_subtasks.empty());
                CompletionToken::operator()(std::forward<Ts>(ts)...);
                async_operation<tags::async_combine_persist>()(
                    get_associated_task());
            } else {
                if (tracked_task_empty()) {
                    CompletionToken::operator()(std::forward<Ts>(ts)...);
                    async_operation<tags::async_combine_persist>()(
                        get_associated_task());
                }
            }
        } catch (const std::exception&) {
            deliver_exception(&get_associated_io_context(),
                              std::current_exception());
            async_operation<tags::async_combine_persist>()(
                get_associated_task());
        }
    }
    template <typename Func> void async_nop(Func&& func) {
        __M_associated_task->get_associated_io_context().async_nop(
            [this, func = std::forward<Func>(func)](
                const std::error_code& ec) mutable { func(*this, ec); });
    }
    constexpr std::size_t tracked_task_num() noexcept(true) {
        return __M_subtasks.size();
    }
    constexpr bool tracked_task_empty() noexcept(true) {
        return __M_subtasks.empty();
    }

    template <typename... Ts> decltype(auto) direct_invoke(Ts&&... ts) {
        return rebind_operation::operator()(*this, std::forward<Ts>(ts)...);
    }

    struct next_guard {
        CHXNET_NONCOPYABLE

        async_combine_impl* self;
        io_context::task_t* task = nullptr;

        constexpr next_guard(async_combine_impl* ptr) noexcept(true)
            : self(ptr) {}
        constexpr next_guard(next_guard&& other) noexcept(true)
            : self(other.self), task(other.task) {
            other.self = nullptr;
            other.task = nullptr;
        }

        void aware(io_context::task_t* t) {
            task = t;
            self->__M_subtasks.push_back(t);
        }
        template <typename... Ts> void operator()(Ts&&... ts) {
            release_and_remove();
            self->direct_invoke(std::forward<Ts>(ts)...);
        }

        void release_and_remove() {
            assert(task);
            self->__M_subtasks.erase(std::find(self->__M_subtasks.begin(),
                                               self->__M_subtasks.end(), task));
            task = nullptr;
        }
    };

    template <typename Tag> struct next_guard_with_tag : next_guard {
        using next_guard::next_guard;

        template <typename... Ts> void operator()(Ts&&... ts) {
            return next_guard::operator()(std::forward<Ts>(ts)..., Tag());
        }
    };

    constexpr auto next() noexcept(true) {
        return task_aware(next_guard(this));
    }
    template <typename Tag> constexpr auto next_with_tag() noexcept(true) {
        return task_aware(next_guard_with_tag<Tag>(this));
    }
    template <typename Tag> constexpr auto next_with_tag(Tag) noexcept(true) {
        return next_with_tag<Tag>();
    }

    template <typename GeneratedToken>
    struct next_then_callable : GeneratedToken {
        template <typename GT>
        next_then_callable(async_combine_impl* s, io_context::task_t* t,
                           GT&& gt)
            : GeneratedToken(std::forward<GT>(gt)), self(s), task(t) {}

        async_combine_impl* self = nullptr;
        io_context::task_t* task = nullptr;

        template <typename... Ts> void operator()(Ts&&... ts) {
            release_and_remove();
            GeneratedToken::operator()(std::forward<Ts>(ts)...);
        }

        void release_and_remove() {
            assert(task);
            self->__M_subtasks.erase(std::find(self->__M_subtasks.begin(),
                                               self->__M_subtasks.end(), task));
            task = nullptr;
        }
    };
    template <typename GT>
    next_then_callable(async_combine_impl*, io_context::task_t*, GT&&)
        -> next_then_callable<std::remove_reference_t<GT>>;

    template <typename FinalFunctor, typename Callable>
    struct next_then_2 : FinalFunctor, Callable {
        template <typename FF, typename C>
        next_then_2(FF&& ff, C&& c)
            : FinalFunctor(std::forward<FF>(ff)), Callable(std::forward<C>(c)) {
        }
        next_then_2(next_then_2&&) = default;

        decltype(auto) operator()(io_context::task_t* t) {
            return FinalFunctor::operator()(static_cast<Callable&>(*this), t);
        }
    };
    template <typename FinalFunctor, typename Callable>
    next_then_2(FinalFunctor&&, Callable&&)
        -> next_then_2<std::remove_reference_t<FinalFunctor>,
                       std::remove_reference_t<Callable>>;

    template <typename BindCompletionToken> struct next_then_1 {
        CHXNET_NONCOPYABLE

        using attribute_type = attribute<async_token>;

        BindCompletionToken bind_completion_token;
        async_combine_impl* self;

        template <typename BCT>
        next_then_1(async_combine_impl* s, BCT&& bct)
            : self(s), bind_completion_token(std::forward<BCT>(bct)) {}

        template <typename FinalFunctor>
        decltype(auto) generate_token(io_context::task_t* task,
                                      FinalFunctor&& final_functor) {
            self->__M_subtasks.push_back(task);
            return next_then_2(
                std::forward<FinalFunctor>(final_functor),
                next_then_callable(
                    self, task,
                    std::move(async_token_generate(
                        task,
                        [](auto& token, task_decl*) -> auto& { return token; },
                        std::forward<BindCompletionToken>(
                            bind_completion_token))(nullptr))));
        }
        template <typename T> decltype(auto) get_init(T t) {
            return async_token_init(t, bind_completion_token);
        }
    };
    template <typename BindCompletionToken>
    next_then_1(async_combine_impl*, BindCompletionToken&&)
        -> next_then_1<std::remove_reference_t<BindCompletionToken&&>>;

    template <typename _CT> struct next_then_0 {
        CHXNET_NONCOPYABLE

        using attribute_type = attribute<async_token>;

        async_combine_impl* self;
        _CT completion_token;

        template <typename CT>
        next_then_0(async_combine_impl* s, CT&& ct)
            : self(s), completion_token(std::forward<CT>(ct)) {}

        template <typename... S> decltype(auto) bind() {
            return next_then_1(self, async_token_bind<S...>(
                                         std::forward<_CT>(completion_token)));
        }
    };
    template <typename CT>
    next_then_0(async_combine_impl*, CT&&) -> next_then_0<CT>;
    template <typename CT>
    next_then_0(async_combine_impl*, CT&) -> next_then_0<CT&>;

    template <typename CT> decltype(auto) next_then(CT&& completion_token) {
        return next_then_0(this, std::forward<CT>(completion_token));
    }
};
template <auto EnableReferenceCount, typename CompletionToken,
          typename Operation, typename... OpArgs, std::size_t... OpArgsI,
          typename InitParam>
async_combine_impl(std::integral_constant<bool, EnableReferenceCount>,
                   io_context::task_t*, CompletionToken&&,
                   type_identity<Operation>, std::tuple<OpArgs...>,
                   std::integer_sequence<std::size_t, OpArgsI...>, InitParam)
    -> async_combine_impl<std::remove_reference_t<Operation>,
                          std::remove_reference_t<CompletionToken>,
                          std::integral_constant<bool, EnableReferenceCount>>;

namespace tags {
struct combine {};
}  // namespace tags

template <> struct async_operation<tags::combine> {
    template <bool EnableReferenceCount, typename Operation, typename... OpArgs,
              typename CompletionToken, typename InitParam>
    decltype(auto) f(io_context& ctx, CompletionToken&& completion_token,
                     type_identity<Operation> opt, std::tuple<OpArgs...> args,
                     InitParam init_param) {
        io_context::task_t* task = ctx.acquire();
        task->__M_cancel_type = task->__CT_invoke_cancel;
        using __ctad_type = decltype(detail::async_combine_impl(
            std::integral_constant<bool, EnableReferenceCount>{}, task,
            std::move(detail::async_token_generate(
                task, [](auto& token, task_decl*) -> auto& { return token; },
                completion_token)(nullptr)),
            opt, std::move(args),
            std::make_integer_sequence<std::size_t, sizeof...(OpArgs)>{},
            std::move(init_param)));
        return detail::async_token_init(
            task->__M_token.emplace<__ctad_type>(
                detail::inplace,
                std::integral_constant<bool, EnableReferenceCount>{}, task,
                std::move(detail::async_token_generate(
                    task,
                    [](auto& token, task_decl*) -> auto& { return token; },
                    completion_token)(nullptr)),
                opt, std::move(args),
                std::make_integer_sequence<std::size_t, sizeof...(OpArgs)>{},
                std::move(init_param)),
            completion_token);
    }
};

}  // namespace detail

/**
 * @brief Helper method to combine multiple async tasks.
 *
 * @note complete() method can only be called once, and only when there is no
 * outstanding async tasks that were submitted by the operation before.
 *
 * @tparam Signature Parameters of the signature of completion_token.
 * @param ctx io_context which will handles the combined async task.
 * @param op Callable object which implements the operations.
 * @param completion_token Callable object which will be called when the
 * combined async tasks completed.
 * @return decltype(auto)
 */
template <typename... Signature, typename Operation, typename... OpArgs,
          typename CompletionToken>
decltype(auto)
async_combine(io_context& ctx, CompletionToken&& completion_token,
              detail::type_identity<Operation> opt, OpArgs&&... args) {
    return detail::async_operation<detail::tags::combine>().f<false>(
        ctx,
        detail::async_token_bind<Signature...>(
            std::forward<CompletionToken>(completion_token)),
        opt, std::tuple<OpArgs&&...>(std::forward<OpArgs>(args)...),
        detail::async_combine_no_init_param{});
}

template <typename... Signature, typename Operation, typename... OpArgs,
          typename CompletionToken>
decltype(auto) async_combine_reference_count(
    io_context& ctx, CompletionToken&& completion_token,
    detail::type_identity<Operation> opt, OpArgs&&... args) {
    return detail::async_operation<detail::tags::combine>().f<true>(
        ctx,
        detail::async_token_bind<Signature...>(
            std::forward<CompletionToken>(completion_token)),
        opt, std::tuple<OpArgs&&...>(std::forward<OpArgs>(args)...),
        detail::async_combine_no_init_param{});
}

template <typename... Signature, typename Operation, typename... OpArgs,
          typename CompletionToken,
          // options
          bool EnableReferenceCount = false,
          typename InitParam = detail::async_combine_no_init_param>
decltype(auto)
async_combine_ng(io_context& ctx, CompletionToken&& completion_token,
                 detail::type_identity<Operation> opt,
                 std::tuple<OpArgs...> args,
                 std::integral_constant<bool, EnableReferenceCount> = {},
                 InitParam init_param = {}) {
    return detail::async_operation<detail::tags::combine>()
        .f<EnableReferenceCount>(
            ctx,
            detail::async_token_bind<Signature...>(
                std::forward<CompletionToken>(completion_token)),
            opt, std::move(args), std::move(init_param));
}

constexpr std::true_type enable_reference_count;
constexpr std::false_type disable_reference_count;
}  // namespace chx::net

#include "./cancellation.hpp"
