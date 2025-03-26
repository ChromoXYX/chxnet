#pragma once

#include "../io_context.hpp"
#include "../ip.hpp"

#include "../detail/io_uring_task_getter.hpp"

namespace chx::net::ip::detail::tags {
struct connect2 {};
struct async_accept {};
}  // namespace chx::net::ip::detail::tags

template <>
struct chx::net::detail::async_operation<chx::net::ip::detail::tags::connect2> {
    template <typename GeneratedCompletionToken>
    struct c3 : GeneratedCompletionToken {
        union {
            struct sockaddr_in in4;
            struct sockaddr_in6 in6;
        } st = {};
        template <typename GCT>
        c3(const sockaddr_in& in4, GCT&& gct)
            : GeneratedCompletionToken(std::forward<GCT>(gct)) {
            st.in4 = in4;
        }
        template <typename GCT>
        c3(const sockaddr_in6& in6, GCT&& gct)
            : GeneratedCompletionToken(std::forward<GCT>(gct)) {
            st.in6 = in6;
        }
    };
    template <typename SockAddr, typename GeneratedCompletionToken>
    c3(const SockAddr&, GeneratedCompletionToken&&)
        -> c3<std::remove_reference_t<GeneratedCompletionToken>>;

    template <typename Protocol, typename BindCompletionToken> struct c2 {
        ip::basic_endpoint<Protocol> endpoint;
        BindCompletionToken bind_completion_token;
        int fd;

        io_context::task_t* task;

        using attribute_type = attribute<async_token>;

        template <typename P, typename BCT>
        c2(const ip::basic_endpoint<P>& ep, BCT&& bct, int f)
            : endpoint(ep), bind_completion_token(std::forward<BCT>(bct)),
              fd(f) {}

        template <typename FinalFunctor>
        decltype(auto) generate_token(io_context::task_t* t,
                                      FinalFunctor&& final_functor) {
            task = t;
            if (endpoint.address().is_v4()) {
                return c3(endpoint.sockaddr_in(),
                          async_token_generate(
                              t, std::forward<FinalFunctor>(final_functor),
                              std::forward<BindCompletionToken>(
                                  bind_completion_token)));
            } else {
                return c3(endpoint.sockaddr_in6(),
                          async_token_generate(
                              t, std::forward<FinalFunctor>(final_functor),
                              std::forward<BindCompletionToken>(
                                  bind_completion_token)));
            }
        }

        template <typename TypeIdentity>
        decltype(auto) get_init(TypeIdentity ti) {
            auto* sqe = task->get_associated_io_context().get_sqe(task);
            auto* d = static_cast<typename TypeIdentity::type*>(
                task->get_underlying_data());
            io_uring_prep_connect(sqe, fd, (const struct sockaddr*)&d->st,
                                  endpoint.address().is_v4()
                                      ? sizeof(sockaddr_in)
                                      : sizeof(sockaddr_in6));
            return async_token_init(
                ti, std::forward<BindCompletionToken>(bind_completion_token));
        }
    };
    template <typename Protocol, typename BindCompletionToken>
    c2(const ip::basic_endpoint<Protocol>&, BindCompletionToken&&, int)
        -> c2<Protocol, BindCompletionToken&&>;

    template <typename CompletionToken>
    decltype(auto) operator()(io_context* ctx,
                              CompletionToken&& completion_token) {
        auto* task = ctx->acquire();
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) mutable -> int {
                    token(get_ec(self));
                    return 0;
                },
                completion_token)),
            completion_token);
    }
};

template <>
struct chx::net::detail::async_operation<
    chx::net::ip::detail::tags::async_accept> {
    template <typename Protocol, typename CompletionToken>
    decltype(auto) f(io_context* ctx, typename Protocol::acceptor* acceptor,
                     CompletionToken&& completion_token) {
        io_context::task_t* task = ctx->acquire();
        auto* sqe = ctx->get_sqe();
        io_uring_sqe_set_data(sqe, task);
        io_uring_prep_accept(sqe, acceptor->native_handler(), nullptr, nullptr,
                             0);

        task->__M_additional_val = reinterpret_cast<std::uint64_t>(acceptor);
        return detail::async_token_init(
            task->__M_token.emplace(detail::async_token_generate(
                task,
                [](auto& completion_token,
                   io_context::task_t* self) mutable -> int {
                    auto* acceptor =
                        reinterpret_cast<typename Protocol::acceptor*>(
                            self->__M_additional_val);
                    int res = get_res(self);
                    completion_token(get_ec(self),
                                     typename Protocol::socket(
                                         acceptor->get_associated_io_context(),
                                         res > 0 ? res : -1));
                    return 0;
                },
                std::forward<CompletionToken>(completion_token))),
            std::forward<CompletionToken>(completion_token));
    }
};
