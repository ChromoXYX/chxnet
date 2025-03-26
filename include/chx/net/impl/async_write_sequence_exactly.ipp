#pragma once

#include "../async_write_sequence_exactly.hpp"
#include "../async_write_sequence.hpp"
#include "../detail/type_identity.hpp"
#include "../detail/span.hpp"

namespace chx::net::detail {
namespace tags {
struct write_seq_exactly {};
}  // namespace tags

template <> struct async_operation<tags::write_seq_exactly> {
    template <typename StreamRef, typename FlatSequence,
              typename CompletionToken>
    static decltype(auto) async_write_seq3(StreamRef& sr,
                                           FlatSequence& flat_seq,
                                           CompletionToken&& completion_token) {
        return sr.async_write_some(
            flat_seq, std::forward<CompletionToken>(completion_token));
    }

    template <typename Stream, typename RealSequence>
    struct exactly_seq_managed {
        CHXNET_NONCOPYABLE
        template <typename CntlType> using rebind = exactly_seq_managed;
        using __toolkit = flatten_sequence_impl;

        template <typename STRM, typename RS>
        exactly_seq_managed(STRM&& strm, RS&& rs)
            : stream(std::forward<STRM>(strm)), real_seq(std::forward<RS>(rs)),
              flat_sequence(flatten_sequence(real_seq)) {
            for (const iovec& i : flat_sequence) {
                total_size += i.iov_len;
            }
        }

        Stream stream;
        RealSequence real_seq;

        flatten_sequence_type<RealSequence> flat_sequence;
        std::size_t transferred = 0;
        std::size_t total_size = 0;
        std::size_t iovec_index = 0;

        template <typename Cntl> void operator()(Cntl& cntl) {
            async_write_seq3(stream, flat_sequence, cntl.next());
        }
        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e, std::size_t s) {
            if (!e && s) {
                if (transferred + s < total_size) {
                    transferred += s;
                    while (iovec_index < flat_sequence.size() &&
                           s >= flat_sequence[iovec_index].iov_len) {
                        s -= flat_sequence[iovec_index++].iov_len;
                    }
                    assert(iovec_index < flat_sequence.size() &&
                           flat_sequence[iovec_index].iov_len > s);
                    flat_sequence[iovec_index].iov_len -= s;
                    span sp(flat_sequence.data() + iovec_index,
                            flat_sequence.size() - iovec_index);
                    async_write_seq3(stream, sp, cntl.next());
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
    if constexpr (!check_attr<detail::no_short_write, std::decay_t<Stream>>()) {
        using operation_type =
            decltype(detail::async_operation<detail::tags::write_seq_exactly>::
                         exactly_seq_managed(std::forward<Stream>(stream),
                                             std::forward<Sequence>(sequence)));
        return async_combine<const std::error_code&, std::size_t>(
            stream.get_associated_io_context(),
            std::forward<CompletionToken>(completion_token),
            detail::type_identity<operation_type>(),
            std::forward<Stream>(stream), std::forward<Sequence>(sequence));
    } else {
        return net::async_write_sequence(
            stream, std::forward<Sequence>(sequence),
            std::forward<CompletionToken>(completion_token));
    }
}
