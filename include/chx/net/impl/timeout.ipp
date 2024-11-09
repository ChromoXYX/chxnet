#pragma once

#include "../timeout.hpp"
#include "../cancellation.hpp"

namespace chx::net::detail {
namespace tags {
struct io_uring_timeout {};
}  // namespace tags

template <> struct async_operation<tags::io_uring_timeout> {
    template <typename CompletionToken> struct wrapper2 {
        CHXNET_NONCOPYABLE
        CompletionToken completion_token;
        cancellation_signal& handler;

        wrapper2(wrapper2&&) = default;
        template <typename CT>
        wrapper2(CT&& ct, cancellation_signal& h)
            : completion_token(std::forward<CT>(ct)), handler(h) {}
    };
    template <typename CompletionToken>
    wrapper2(CompletionToken&&, cancellation_signal&)
        -> wrapper2<std::remove_reference_t<CompletionToken>>;

    template <typename CompletionToken>
    static constexpr decltype(auto)
    to_wrapper2(CompletionToken&& completion_token) {
        if constexpr (check_attr<cancellation_attr,
                                 std::decay_t<CompletionToken>>()) {
            return wrapper2(std::move(completion_token.bind_completion_token),
                            completion_token.signal);
        } else {
            return std::forward<CompletionToken>(completion_token);
        }
    }

    template <typename GeneratedCompletionToken>
    struct to2 : GeneratedCompletionToken {
        struct __kernel_timespec ts;

        template <typename GCT>
        to2(GCT&& gct, const struct __kernel_timespec& t)
            : GeneratedCompletionToken(std::forward<GCT>(gct)), ts(t) {}
    };
    template <typename GeneratedCompletionToken>
    to2(GeneratedCompletionToken&&, const struct __kernel_timespec&)
        -> to2<std::remove_reference_t<GeneratedCompletionToken>>;

    template <typename BindCompletionToken> struct to1 {
        BindCompletionToken bind_completion_token;
        std::chrono::nanoseconds dur;
        io_context::task_t* task = nullptr;

        using attribute_type = attribute<async_token>;

        template <typename BCT>
        to1(BCT&& bct, const std::chrono::nanoseconds d)
            : bind_completion_token(std::forward<BCT>(bct)), dur(d) {}

        template <typename FinalFunctor>
        constexpr decltype(auto) generate_token(io_context::task_t* task,
                                                FinalFunctor&& final_functor) {
            this->task = task;
            struct __kernel_timespec ts = {};
            auto secs = std::chrono::duration_cast<std::chrono::seconds>(dur);
            ts.tv_sec = secs.count();
            ts.tv_nsec =
                std::chrono::duration_cast<std::chrono::nanoseconds>(dur - secs)
                    .count();
            return to2(async_token_generate(
                           task, std::forward<FinalFunctor>(final_functor),
                           bind_completion_token),
                       ts);
        }

        template <typename TypeIdentity>
        constexpr decltype(auto) get_init(TypeIdentity ti) {
            auto* sqe = task->get_associated_io_context().get_sqe(task);
            auto* underlying = static_cast<typename TypeIdentity::type*>(
                task->get_underlying_data());
            io_uring_prep_timeout(sqe, &underlying->ts, 0, 0);
            return async_token_init(ti, bind_completion_token);
        }
    };
    template <typename BindCompletionToken>
    struct to1<wrapper2<BindCompletionToken>> {
        wrapper2<BindCompletionToken> wrapper_;
        std::chrono::nanoseconds dur;
        io_context::task_t* task = nullptr;

        using attribute_type = attribute<async_token>;

        template <typename T>
        to1(T&& t, const std::chrono::nanoseconds& d)
            : wrapper_(std::forward<T>(t)), dur(d) {}

        template <typename FinalFunctor>
        constexpr decltype(auto) generate_token(io_context::task_t* task,
                                                FinalFunctor&& final_functor) {
            this->task = task;
            struct __kernel_timespec ts = {};
            auto secs = std::chrono::duration_cast<std::chrono::seconds>(dur);
            ts.tv_sec = secs.count();
            ts.tv_nsec =
                std::chrono::duration_cast<std::chrono::nanoseconds>(dur - secs)
                    .count();
            return to2(async_token_generate(
                           task, std::forward<FinalFunctor>(final_functor),
                           wrapper_.completion_token),
                       ts);
        }

        template <typename TypeIdentity>
        constexpr decltype(auto) get_init(TypeIdentity ti) {
            auto* sqe = task->get_associated_io_context().get_sqe(task);
            auto* underlying = static_cast<typename TypeIdentity::type*>(
                task->get_underlying_data());
            io_uring_prep_timeout(sqe, &underlying->ts, 0, 0);
            wrapper_.handler.emplace(
                std::make_unique<timeout_cancellation>(task));
            return async_token_init(ti, wrapper_.completion_token);
        }
    };

    template <typename T>
    to1(wrapper2<T>&&, const std::chrono::nanoseconds&) -> to1<wrapper2<T>>;
    template <typename T>
    to1(T&&, const std::chrono::nanoseconds&)
        -> to1<std::remove_reference_t<T>>;

    template <typename CompletionToken> struct to0 {
        CompletionToken completion_token;
        std::chrono::nanoseconds dur;

        using attribute_type = attribute<async_token>;

        template <typename CT, typename Rep, typename Period>
        to0(CT&& ct, const std::chrono::duration<Rep, Period>& d)
            : completion_token(std::forward<CT>(ct)),
              dur(std::chrono::duration_cast<std::chrono::nanoseconds>(d)) {}

        template <typename... S> constexpr decltype(auto) bind() {
            return to1(to_wrapper2(async_token_bind<S...>(
                           std::forward<CompletionToken>(completion_token))),
                       dur);
        }
    };
    template <typename T, typename Rep, typename Period>
    to0(T&&, const std::chrono::duration<Rep, Period>&)
        -> to0<std::remove_reference_t<T>>;

    template <typename CompletionToken>
    decltype(auto) operator()(io_context* ctx,
                              CompletionToken&& completion_token) {
        io_context::task_t* task = ctx->acquire();
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) mutable {
                    if (self->__M_res == -errc::stream_timeout) {
                        token(std::error_code{});
                    } else {
                        token(self->__M_ec);
                    }
                    return 0;
                },
                std::forward<CompletionToken>(completion_token))),
            std::forward<CompletionToken>(completion_token));
    }

    template <typename BindCompletionToken> struct upd1 {
        BindCompletionToken bind_completion_token;
        std::chrono::nanoseconds dur;
        io_context::task_t* userdata = nullptr;
        io_context::task_t* task = nullptr;

        using attribute_type = attribute<async_token>;

        template <typename BCT>
        upd1(BCT&& bct, const std::chrono::nanoseconds& d,
             io_context::task_t* ud)
            : bind_completion_token(std::forward<BCT>(bct)), dur(d),
              userdata(ud) {}

        template <typename FinalFunctor>
        constexpr decltype(auto) generate_token(io_context::task_t* task,
                                                FinalFunctor&& final_functor) {
            this->task = task;
            struct __kernel_timespec ts = {};
            auto secs = std::chrono::duration_cast<std::chrono::seconds>(dur);
            ts.tv_sec = secs.count();
            ts.tv_nsec =
                std::chrono::duration_cast<std::chrono::nanoseconds>(dur - secs)
                    .count();
            return to2(async_token_generate(
                           task, std::forward<FinalFunctor>(final_functor),
                           bind_completion_token),
                       ts);
        }

        template <typename TypeIdentity>
        constexpr decltype(auto) get_init(TypeIdentity ti) {
            auto* sqe = task->get_associated_io_context().get_sqe(task);
            auto* underlying = static_cast<typename TypeIdentity::type*>(
                task->get_underlying_data());
            // io_uring_prep_timeout(sqe, &underlying->ts, 0, 0);
            io_uring_prep_timeout_update(
                sqe, &underlying->ts, reinterpret_cast<std::uint64_t>(userdata),
                0);
            return async_token_init(ti, bind_completion_token);
        }
    };
    template <typename T>
    upd1(T&&, const std::chrono::nanoseconds&, io_context::task_t*)
        -> upd1<std::remove_reference_t<T>>;

    template <typename CompletionToken> struct upd0 {
        CompletionToken completion_token;
        std::chrono::nanoseconds dur;
        io_context::task_t* userdata = nullptr;

        using attribute_type = attribute<async_token>;

        template <typename CT, typename Rep, typename Period>
        upd0(CT&& ct, const std::chrono::duration<Rep, Period>& d,
             io_context::task_t* ud)
            : completion_token(std::forward<CT>(ct)),
              dur(std::chrono::duration_cast<std::chrono::nanoseconds>(d)),
              userdata(ud) {}

        template <typename... S> constexpr decltype(auto) bind() {
            return upd1(async_token_bind<S...>(
                            std::forward<CompletionToken>(completion_token)),
                        dur, userdata);
        }
    };
    template <typename T, typename Rep, typename Period>
    upd0(T&&, const std::chrono::duration<Rep, Period>&, io_context::task_t*)
        -> upd0<std::remove_reference_t<T>>;

    template <typename CompletionToken>
    decltype(auto) upd(io_context* ctx, CompletionToken&& completion_token) {
        io_context::task_t* task = ctx->acquire();
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) mutable {
                    token(self->__M_ec);
                    return 0;
                },
                std::forward<CompletionToken>(completion_token))),
            std::forward<CompletionToken>(completion_token));
    }

    template <typename CompletionToken>
    decltype(auto) del(io_context* ctx, io_context::task_t* userdata,
                       CompletionToken&& completion_token) {
        auto [sqe, task] = ctx->get();
        io_uring_prep_timeout_remove(
            sqe, reinterpret_cast<std::uint64_t>(userdata), 0);
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) mutable {
                    token(self->__M_ec);
                    return 0;
                },
                completion_token)),
            completion_token);
    }
};
}  // namespace chx::net::detail

template <typename Rep, typename Period, typename CompletionToken>
decltype(auto)
chx::net::async_timeout(io_context& ctx,
                        const std::chrono::duration<Rep, Period>& dur,
                        CompletionToken&& completion_token) {
    using aop = detail::async_operation<detail::tags::io_uring_timeout>;
    return aop()(&ctx,
                 detail::async_token_bind<const std::error_code&>(aop::to0(
                     std::forward<CompletionToken>(completion_token), dur)));
}

template <typename Rep, typename Period, typename CompletionToken>
decltype(auto) chx::net::timeout_cancellation::async_update(
    const std::chrono::duration<Rep, Period>& dur,
    CompletionToken&& completion_token) {
    using aop = detail::async_operation<detail::tags::io_uring_timeout>;
    return aop().upd(
        &self->get_associated_io_context(),
        detail::async_token_bind<const std::error_code&>(aop::upd0(
            std::forward<CompletionToken>(completion_token), dur, self)));
}

template <typename CompletionToken>
decltype(auto) chx::net::timeout_cancellation::async_remove(
    CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::io_uring_timeout>().del(
        &self->get_associated_io_context(), self,
        detail::async_token_bind<const std::error_code&>(
            std::forward<CompletionToken>(completion_token)));
}
