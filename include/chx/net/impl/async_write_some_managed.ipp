#pragma once

#include "../managed.hpp"

#include "../io_context.hpp"
#include "../async_combine.hpp"

namespace chx::net::detail::tags {
struct write_managed {};
}  // namespace chx::net::detail::tags

template <>
struct chx::net::detail::async_operation<
    chx::net::detail::tags::write_managed> {
    template <typename CompletionToken>
    static void nop(io_context* ctx, CompletionToken&& completion_token) {
        auto [sqe, task] = ctx->get();
        sqe->flags |= IOSQE_IO_LINK;
        io_uring_prep_nop(sqe);
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) mutable -> int {
                    token(self->__M_ec);
                    return 0;
                },
                completion_token)),
            completion_token);
    }

    template <typename Stream, typename Container> struct operation {
        Stream stream;
        Container container;

        template <typename Cntl> void operator()(Cntl& cntl) {
            io_context& ctx = stream.get_associated_io_context();
            nop(&ctx, async_token_bind<const std::error_code&>(cntl.next()));
            unsigned int low_boundary = ctx.__M_ring.sq.sqe_head;
            stream.async_write_some(buffer(container), cntl.next());
            if (low_boundary != ctx.__M_ring.sq.sqe_head) {
                ctx.submit();
            }
        }

        template <typename S, typename C>
        operation(S&& s, C&& c)
            : stream(std::forward<S>(s)), container(std::forward<C>(c)) {}

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code&) {
            container.clear();
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e, std::size_t s) {
            cntl.complete(e, s);
        }
    };
    template <typename Stream, typename Container>
    operation(Stream&, Container&&)
        -> operation<Stream&, std::decay_t<Container>>;
    template <typename Stream, typename Container>
    operation(Stream&&, Container&&)
        -> operation<Stream, std::decay_t<Container>>;
};

template <typename Stream, typename Container, typename CompletionToken>
decltype(auto)
chx::net::async_write_some_managed(Stream&& stream, Container&& container,
                                   CompletionToken&& completion_token) {
    using operation_type =
        decltype(detail::async_operation<detail::tags::write_managed>::
                     operation(std::forward<Stream>(stream),
                               std::forward<Container>(container)));
    return async_combine<const std::error_code&, std::size_t>(
        stream.get_associated_io_context(),
        std::forward<CompletionToken>(completion_token),
        detail::type_identity<operation_type>(), std::forward<Stream>(stream),
        std::forward<Container>(container));
}
