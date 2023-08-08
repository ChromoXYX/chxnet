#pragma once

#include "../managed.hpp"

#include "../async_write_sequence.hpp"
#include "../async_combine.hpp"

namespace chx::net::detail {
namespace tags {
struct write_seq_managed {};
}  // namespace tags

template <> struct async_operation<tags::write_seq_managed> {
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

    template <typename Stream, typename Sequence, typename CntlType = void>
    struct operation {
        Stream stream;
        Sequence sequence;

        template <typename T> using rebind = operation<Stream, Sequence, T>;

        template <typename S, typename Seq>
        operation(S&& s, Seq&& seq)
            : stream(std::forward<S>(s)), sequence(std::forward<Seq>(seq)) {}

        template <typename Cntl> void operator()(Cntl& cntl) {
            static_assert(!std::is_same_v<CntlType, void>);
            io_context& ctx = stream.get_associated_io_context();
            nop(&ctx, async_token_bind<const std::error_code&>(cntl.next()));
            unsigned int low_boundary = ctx.__M_ring.sq.sqe_head;
            async_write_sequence(stream, sequence, cntl.next());
            if (low_boundary != ctx.__M_ring.sq.sqe_head) {
                ctx.submit();
            }
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e) {
            sequence = {};
        }
        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e, std::size_t s) {
            cntl.complete(e, s);
        }
    };
    template <typename Stream, typename Sequence>
    operation(Stream&, Sequence&&)
        -> operation<Stream&, std::remove_reference_t<Sequence>>;
    template <typename Stream, typename Sequence>
    operation(Stream&&, Sequence&&)
        -> operation<Stream, std::remove_reference_t<Sequence>>;
};
}  // namespace chx::net::detail

template <typename Stream, typename Sequence, typename CompletionToken>
decltype(auto)
chx::net::async_write_sequence_managed(Stream&& stream, Sequence&& sequence,
                                       CompletionToken&& completion_token) {
    using operation_type =
        decltype(detail::async_operation<detail::tags::write_seq_managed>::
                     operation(std::forward<Stream>(stream),
                               std::forward<Sequence>(sequence)));
    return async_combine_reference_count<const std::error_code&, std::size_t>(
        stream.get_associated_io_context(),
        std::forward<CompletionToken>(completion_token),
        detail::type_identity<operation_type>(), std::forward<Stream>(stream),
        std::forward<Sequence>(sequence));
}
