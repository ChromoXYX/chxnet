#pragma once

#include "./io_context.hpp"
#include "./async_token.hpp"
#include "./attribute.hpp"
#include "./detail/task_aware.hpp"
#include "./detail/type_identity.hpp"

#include <algorithm>

namespace chx::net {
namespace detail {
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
          typename EnableReferenceCount = std::false_type>
struct async_combine_impl
    : Operation::template rebind<
          async_combine_impl<Operation, CompletionToken, EnableReferenceCount>>,
      CompletionToken,
      CHXNET_NONCOPYABLE {
    using attribute_type = attribute<async_token>;
    using rebind_operation =
        typename Operation::template rebind<async_combine_impl>;

    io_context::task_t* const __M_associated_task;
    std::vector<io_context::task_t*> __M_subtasks;

    template <typename OpType, typename... OpArgs, typename C>
    constexpr async_combine_impl(io_context::task_t* task, C&& c,
                                 type_identity<OpType>, OpArgs&&... args)
        : __M_associated_task(task),
          rebind_operation(std::forward<OpArgs>(args)...),
          CompletionToken(std::forward<C>(c)) {
        // may be dangerous?
        // if async_combine is cancelled, would async_nop invoke it?
        // may not, since when token_storage is destructing, the inner functor
        // will not be invoked. and at this time, async_combine cannot be
        // cancelled by io_uring.
        // __M_associated_task->get_associated_io_context().async_nop(next());
        async_operation<tags::async_combine_use_delivery>()(
            &get_associated_io_context(),
            [](auto& token, io_context::task_t* self) mutable -> int {
                if (!self->__M_ec) {
                    token();
                }
                return 0;
            },
            next());
        // direct_invoke();
    }
    template <typename OpType, typename... OpArgs, typename C>
    constexpr async_combine_impl(std::true_type, io_context::task_t* task,
                                 C&& c, type_identity<OpType>, OpArgs&&... args)
        : __M_associated_task(task),
          rebind_operation(std::forward<OpArgs>(args)...),
          CompletionToken(std::forward<C>(c)) {
        async_operation<tags::async_combine_use_delivery>()(
            &get_associated_io_context(),
            [](auto& token, io_context::task_t* self) mutable -> int {
                if (!self->__M_ec) {
                    token();
                }
                return 0;
            },
            next());
    }

    ~async_combine_impl() {
        for (auto* subtask : __M_subtasks) {
            subtask->__M_token.emplace(
                [](io_context::task_t*) -> int { return 0; });
        }
    }

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
    template <typename... Ts> decltype(auto) complete(Ts&&... ts) {
        if constexpr (!EnableReferenceCount::value) {
            if (!__M_subtasks.empty()) {
                __CHXNET_THROW(EINVAL);
            }
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

    struct next_guard : CHXNET_NONCOPYABLE {
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
        ~next_guard() {
            // it's not possible to figure out whether the async_combine_impl
            // still exists.
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

    template <typename BindCompletionToken>
    struct next_then_1 : CHXNET_NONCOPYABLE {
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
                next_then_callable(self, task,
                                   std::move(async_token_generate(
                                       task, __CHXNET_FAKE_FINAL_FUNCTOR(),
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

    template <typename _CT> struct next_then_0 : CHXNET_NONCOPYABLE {
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
template <typename CompletionToken, typename Operation, typename... OpArgs>
async_combine_impl(io_context::task_t*, CompletionToken&&,
                   type_identity<Operation>, OpArgs&&...)
    -> async_combine_impl<std::remove_reference_t<Operation>,
                          std::remove_reference_t<CompletionToken>>;
template <typename CompletionToken, typename Operation, typename... OpArgs>
async_combine_impl(std::true_type, io_context::task_t*, CompletionToken&&,
                   type_identity<Operation>, OpArgs&&...)
    -> async_combine_impl<std::remove_reference_t<Operation>,
                          std::remove_reference_t<CompletionToken>,
                          std::true_type>;

namespace tags {
struct combine {};
}  // namespace tags

template <> struct async_operation<tags::combine> {
    template <typename Operation, typename... OpArgs, typename CompletionToken>
    decltype(auto) operator()(io_context& ctx,
                              CompletionToken&& completion_token,
                              type_identity<Operation> opt, OpArgs&&... args) {
        io_context::task_t* task = ctx.acquire();

        task->__M_persist = true;
        task->__M_cancel_invoke = true;
        using __ctad_type = decltype(detail::async_combine_impl(
            task,
            std::move(detail::async_token_generate(
                task, __CHXNET_FAKE_FINAL_FUNCTOR(),
                completion_token)(nullptr)),
            opt, std::forward<OpArgs>(args)...));
        return detail::async_token_init(
            task->__M_token.emplace<__ctad_type>(
                detail::inplace, task,
                std::move(detail::async_token_generate(
                    task, __CHXNET_FAKE_FINAL_FUNCTOR(),
                    completion_token)(nullptr)),
                opt, std::forward<OpArgs>(args)...),
            completion_token);
    }
    template <typename Operation, typename... OpArgs, typename CompletionToken>
    decltype(auto) ref_count(io_context& ctx,
                             CompletionToken&& completion_token,
                             type_identity<Operation> opt, OpArgs&&... args) {
        io_context::task_t* task = ctx.acquire();

        task->__M_persist = true;
        task->__M_cancel_invoke = true;
        using __ctad_type = decltype(detail::async_combine_impl(
            std::true_type{}, task,
            std::move(detail::async_token_generate(
                task, __CHXNET_FAKE_FINAL_FUNCTOR(),
                completion_token)(nullptr)),
            opt, std::forward<OpArgs>(args)...));
        return detail::async_token_init(
            task->__M_token.emplace<__ctad_type>(
                detail::inplace, std::true_type{}, task,
                std::move(detail::async_token_generate(
                    task, __CHXNET_FAKE_FINAL_FUNCTOR(),
                    completion_token)(nullptr)),
                opt, std::forward<OpArgs>(args)...),
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
    return detail::async_operation<detail::tags::combine>()(
        ctx,
        detail::async_token_bind<Signature...>(
            std::forward<CompletionToken>(completion_token)),
        opt, std::forward<OpArgs>(args)...);
}

template <typename... Signature, typename Operation, typename... OpArgs,
          typename CompletionToken>
decltype(auto) async_combine_reference_count(
    io_context& ctx, CompletionToken&& completion_token,
    detail::type_identity<Operation> opt, OpArgs&&... args) {
    return detail::async_operation<detail::tags::combine>().ref_count(
        ctx,
        detail::async_token_bind<Signature...>(
            std::forward<CompletionToken>(completion_token)),
        opt, std::forward<OpArgs>(args)...);
}
}  // namespace chx::net

#include "./cancellation.hpp"
