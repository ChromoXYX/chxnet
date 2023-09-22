#pragma once

#include "../async_write_sequence_exactly.hpp"
#include "../async_write_sequence.hpp"
#include "../detail/type_identity.hpp"

namespace chx::net::detail {
namespace tags {
struct write_seq_exactly {};
}  // namespace tags

template <> struct async_operation<tags::write_seq_exactly> {
    template <typename StreamRef, typename FlatSequence,
              typename BindCompletionToken>
    static decltype(auto)
    async_write_seq2_2(StreamRef& sr, FlatSequence& flat_seq,
                       BindCompletionToken&& completion_token) {
        auto [sqe, task] = sr.get_associated_io_context().get();
        io_uring_prep_writev(sqe, sr.native_handler(), flat_seq.data(),
                             flat_seq.size(), 0);
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) -> int {
                    token(self->__M_ec, self->__M_res);
                    return 0;
                },
                completion_token)),
            completion_token);
    }
    template <typename StreamRef, typename FlatSequence,
              typename CompletionToken>
    static decltype(auto) async_write_seq2(StreamRef& sr,
                                           FlatSequence& flat_seq,
                                           CompletionToken&& completion_token) {
        return async_write_seq2_2(
            sr, flat_seq,
            async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)));
    }

    template <typename Stream, typename RealSequence>
    struct exactly_seq_managed : CHXNET_NONCOPYABLE {
        template <typename CntlType> using rebind = exactly_seq_managed;
        using __toolkit = async_operation<tags::async_write_seq>;

        template <typename STRM, typename RS>
        exactly_seq_managed(STRM&& strm, RS&& rs)
            : stream(std::forward<STRM>(strm)), real_seq(std::forward<RS>(rs)),
              flat_sequence(__toolkit::iov_static_size(real_seq)) {
            struct iovec* ptr = flat_sequence.data();
            __toolkit::arr_fill(real_seq, ptr);
            for (const iovec& i : flat_sequence) {
                total_size += i.iov_len;
            }
        }

        Stream stream;
        RealSequence real_seq;

        using flat_sequence_type = std::vector<struct iovec>;
        flat_sequence_type flat_sequence;
        std::size_t transferred = 0;
        std::size_t total_size = 0;

        template <typename Cntl> void operator()(Cntl& cntl) {
            async_write_seq2(stream, flat_sequence, cntl.next());
        }
        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e, std::size_t s) {
            if (!e && s) {
                if (transferred + s < total_size) {
                    while (s >= flat_sequence.front().iov_len) {
                        s -= flat_sequence.front().iov_len;
                        flat_sequence.erase(flat_sequence.begin());
                    }
                    transferred += s;
                    flat_sequence.front().iov_len -= s;
                    async_write_seq2(stream, flat_sequence, cntl.next());
                } else {
                    cntl.complete(e, total_size);
                }
            } else {
                cntl.complete(e, transferred);
            }
        }
    };
    template <typename Stream, typename RealSequence>
    exactly_seq_managed(Stream&&, RealSequence&&) -> exactly_seq_managed<
        std::conditional_t<std::is_lvalue_reference_v<Stream&&>, Stream&&,
                           std::remove_reference_t<Stream&&>>,
        std::conditional_t<std::is_lvalue_reference_v<RealSequence&&>,
                           RealSequence&&,
                           std::remove_reference_t<RealSequence&&>>>;
};
}  // namespace chx::net::detail

template <typename Stream, typename Sequence, typename CompletionToken>
decltype(auto)
chx::net::async_write_sequence_exactly(Stream&& stream, Sequence&& sequence,
                                       CompletionToken&& completion_token) {
    using operation_type =
        decltype(detail::async_operation<detail::tags::write_seq_exactly>::
                     exactly_seq_managed(std::forward<Stream>(stream),
                                         std::forward<Sequence>(sequence)));
    return async_combine<const std::error_code&, std::size_t>(
        stream.get_associated_io_context(),
        std::forward<CompletionToken>(completion_token),
        detail::type_identity<operation_type>(), std::forward<Stream>(stream),
        std::forward<Sequence>(sequence));
}