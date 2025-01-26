#pragma once

#include "../async_openat.hpp"

#include "../file.hpp"

namespace chx::net::detail {
namespace tags {
struct openat {};
}  // namespace tags

template <> struct async_operation<tags::openat> {
    template <typename GeneratedCompletionToken>
    struct openat_impl2 : GeneratedCompletionToken {
        const std::string pathname;
        struct open_how how;

        template <typename Pathname, typename GCT>
        openat_impl2(Pathname&& p, const open_how& h, GCT&& gct)
            : pathname(std::forward<Pathname>(p)), how(h),
              GeneratedCompletionToken(std::forward<GCT>(gct)) {}
    };
    template <typename Pathname, typename GeneratedCompletionToken>
    openat_impl2(Pathname&&, const open_how& h, GeneratedCompletionToken&&)
        -> openat_impl2<std::remove_reference_t<GeneratedCompletionToken>>;
    template <typename Pathname, typename BindCompletionToken>
    struct openat_impl1 {
        Pathname pathname;
        const open_how& how;
        const int dirfd;
        BindCompletionToken bind_completion_token;

        io_context::task_t* task;

        using attribute_type = attribute<async_token>;

        template <typename P, typename BCT>
        openat_impl1(P&& p, const open_how& h, int d, BCT&& bct)
            : pathname(std::forward<P>(p)), how(h), dirfd(d),
              bind_completion_token(std::forward<BCT>(bct)) {}

        template <typename FinalFunctor>
        decltype(auto) generate_token(io_context::task_t* t,
                                      FinalFunctor&& final_functor) {
            task = t;
            return openat_impl2(
                std::forward<Pathname>(pathname), how,
                async_token_generate(
                    task, std::forward<FinalFunctor>(final_functor),
                    std::forward<BindCompletionToken>(bind_completion_token)));
        }

        template <typename TypeIdentity>
        decltype(auto) get_init(TypeIdentity ti) {
            auto* sqe = task->get_associated_io_context().get_sqe(task);
            auto* ptr = static_cast<typename TypeIdentity::type*>(
                task->get_underlying_data());
            io_uring_prep_openat2(sqe, dirfd, ptr->pathname.data(), &ptr->how);
            return async_token_init(
                ti, std::forward<BindCompletionToken>(bind_completion_token));
        }
    };
    template <typename Pathname, typename BindCompletionToken>
    openat_impl1(Pathname&&, const open_how& h, int d, BindCompletionToken&&)
        -> openat_impl1<Pathname&&, BindCompletionToken&&>;

    template <typename CompletionToken>
    decltype(auto) operator()(io_context* ctx,
                              CompletionToken&& completion_token) {
        auto* task = ctx->acquire();
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) mutable -> int {
                    token(get_ec(self),
                          file(self->get_associated_io_context(),
                               get_res(self) > 0 ? get_res(self) : -1));
                    return 0;
                },
                completion_token)),
            completion_token);
    }
};
}  // namespace chx::net::detail

template <typename Pathname, typename CompletionToken>
decltype(auto) chx::net::async_openat(io_context& ctx,
                                      const file_descriptor& dir,
                                      Pathname&& pathname, const open_how& how,
                                      CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::openat>()(
        &ctx, detail::async_operation<detail::tags::openat>::openat_impl1(
                  std::forward<Pathname>(pathname), how, dir.native_handler(),
                  detail::async_token_bind<const std::error_code&, file>(
                      std::forward<CompletionToken>(completion_token))));
}
