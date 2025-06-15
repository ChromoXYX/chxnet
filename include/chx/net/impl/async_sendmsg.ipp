#pragma once

#include "../async_sendmsg.hpp"
#include "../async_operation.hpp"
#include "../io_context.hpp"
#include "../async_token.hpp"
#include "../detail/task_carrier.hpp"
#include "../type_traits/flatten_sequence.hpp"
#include "../type_traits/remove_rvalue_reference.hpp"
#include "../detail/span.hpp"
#include "./write_exactly.hpp"

namespace chx::net::detail {
namespace tags {
struct sendmsg {};
}  // namespace tags

template <> struct async_operation<tags::sendmsg> {
    template <typename BindCompletionToken>
    decltype(auto) operator()(io_context* ctx,
                              BindCompletionToken&& bind_completion_token) {
        task_decl* task = ctx->acquire();
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, task_decl* self) -> int {
                    const io_uring_cqe* cqe = self->__M_cqe;
                    const int res = cqe->res;
                    token(res >= 0 ? std::error_code{} : make_ec(-res), res);
                    return 0;
                },
                bind_completion_token)),
            bind_completion_token);
    }

    template <typename BindCompletionToken>
    decltype(auto) zero_copy(io_context* ctx,
                             BindCompletionToken&& bind_completion_token) {
        task_decl* task = ctx->acquire();
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [res = 0](auto& token, task_decl* self) mutable -> int {
                    if (res == 0) {
                        res = self->__M_cqe->res;
                    }
                    if (!(self->__M_cqe->flags & IORING_CQE_F_MORE)) {
                        token(res >= 0 ? std::error_code{} : make_ec(-res),
                              res);
                    }
                    return 0;
                },
                bind_completion_token)),
            bind_completion_token);
    }

    template <typename Socket, typename RealSequence, typename CntlType = int>
    struct operation
        : write_exactly<RealSequence,
                        operation<Socket, RealSequence, CntlType>> {
        CHXNET_NONCOPYABLE
        template <typename T> using rebind = operation<Socket, RealSequence, T>;

        constexpr CntlType& cntl() noexcept(true) {
            return static_cast<CntlType&>(*this);
        }

        template <typename STRM, typename RS>
        operation(STRM&& strm, RS&& rs)
            : write_exactly<RealSequence,
                            operation<Socket, RealSequence, CntlType>>(
                  std::forward<RS>(rs)),
              socket(std::forward<STRM>(strm)) {}

        Socket socket;

        void do_write(span<struct iovec> sp) {
            async_sendmsg_zero_copy(cntl().get_associated_io_context(), socket,
                                    make_msghdr(sp), cntl().next());
        }

        constexpr struct msghdr
        make_msghdr(span<struct iovec> sp) noexcept(true) {
            struct msghdr msghdr = {};
            msghdr.msg_iov = sp.data();
            msghdr.msg_iovlen = sp.size();
            return msghdr;
        }
    };
    template <typename Stream, typename RealSequence>
    operation(Stream&&, RealSequence&&)
        -> operation<typename remove_rvalue_reference<Stream&&>::type,
                     typename remove_rvalue_reference<RealSequence&&>::type>;
};
}  // namespace chx::net::detail

template <typename Socket, typename CompletionToken>
decltype(auto) chx::net::async_sendmsg(io_context& ctx, Socket& socket,
                                       const msghdr& msghdr,
                                       CompletionToken&& completion_token) {
    struct msghdr opts = msghdr;
    opts.msg_iovlen = std::min(std::size_t{IOV_MAX}, opts.msg_iovlen);
    return detail::async_operation<detail::tags::sendmsg>()(
        &ctx,
        detail::task_carrier_s2(
            detail::async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)),
            opts, [&socket](task_decl* task, auto ti, struct msghdr* msghdr) {
                io_context* ctx = &task->get_associated_io_context();
                io_uring_sqe* sqe = ctx->get_sqe(task);
                io_uring_prep_sendmsg(sqe, socket.native_handler(), msghdr, 0);
            }));
}

template <typename Socket, typename CompletionToken>
decltype(auto)
chx::net::async_sendmsg_zero_copy(io_context& ctx, Socket& socket,
                                  const msghdr& msghdr,
                                  CompletionToken&& completion_token) {
    struct msghdr opts = msghdr;
    opts.msg_iovlen = std::min(std::size_t{IOV_MAX}, opts.msg_iovlen);
    return detail::async_operation<detail::tags::sendmsg>().zero_copy(
        &ctx,
        detail::task_carrier_s2(
            detail::async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)),
            opts, [&socket](task_decl* task, auto ti, struct msghdr* msghdr) {
                io_context* ctx = &task->get_associated_io_context();
                io_uring_sqe* sqe = ctx->get_sqe(task);
                io_uring_prep_sendmsg(sqe, socket.native_handler(), msghdr, 0);
            }));
}

template <typename Socket, typename Sequence, typename CompletionToken>
decltype(auto)
chx::net::async_sendmsg_zero_copy_exactly(io_context& ctx, Socket& socket,
                                          Sequence&& sequence,
                                          CompletionToken&& completion_token) {
    using operation_type =
        decltype(detail::async_operation<detail::tags::sendmsg>::operation(
            std::forward<Socket>(socket), std::forward<Sequence>(sequence)));
    return async_combine<const std::error_code&, std::size_t>(
        socket.get_associated_io_context(),
        std::forward<CompletionToken>(completion_token),
        detail::type_identity<operation_type>(), std::forward<Socket>(socket),
        std::forward<Sequence>(sequence));
}
