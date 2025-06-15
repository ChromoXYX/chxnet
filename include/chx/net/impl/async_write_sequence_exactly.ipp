#pragma once

#include "../async_write_sequence_exactly.hpp"
#include "../async_write_sequence.hpp"
#include "../detail/type_identity.hpp"
#include "../detail/span.hpp"
#include "./write_exactly.hpp"

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

    template <typename Stream, typename RealSequence, typename CntlType = int>
    struct exactly_seq_managed
        : write_exactly<RealSequence,
                        exactly_seq_managed<Stream, RealSequence, CntlType>> {
        CHXNET_NONCOPYABLE
        template <typename T>
        using rebind = exactly_seq_managed<Stream, RealSequence, T>;

        constexpr CntlType& cntl() noexcept(true) {
            return static_cast<CntlType&>(*this);
        }

        using __toolkit = flatten_sequence_impl;

        template <typename STRM, typename RS>
        exactly_seq_managed(STRM&& strm, RS&& rs)
            : write_exactly<RealSequence, exactly_seq_managed<
                                              Stream, RealSequence, CntlType>>(
                  std::forward<RS>(rs)),
              stream(std::forward<STRM>(strm)) {}

        Stream stream;

        void do_write(span<struct iovec> sp) {
            stream.async_write_some(sp, cntl().next());
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
