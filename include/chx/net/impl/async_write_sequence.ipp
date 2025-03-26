#pragma once

#include "../async_write_sequence.hpp"

#include "../io_context.hpp"
#include "../async_combine.hpp"
#include "../detail/flatten_sequence.hpp"

namespace chx::net::detail {
// now, stream.async_write_some(seq) ->  not managed
//      net::async_write_sequence(seq) ->    managed
//      net::async_write_sequence_exactly -> managed

namespace tags {
struct async_write_seq {};
}  // namespace tags

template <> struct async_operation<tags::async_write_seq> {
    template <typename Stream, typename Sequence> struct operation {
        template <typename Cntl> using rebind = operation;

        Stream stream;
        Sequence sequence;
        flatten_sequence_type<Sequence> iov_arr;

        template <typename STRM, typename Seq>
        operation(STRM&& strm, Seq&& seq)
            : stream(std::forward<STRM>(strm)),
              sequence(std::forward<Seq>(seq)), iov_arr(fill_iov(sequence)) {}

        template <typename Cntl> void operator()(Cntl& cntl) {
            stream.async_write_some(iov_arr, cntl.next());
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e, std::size_t s) {
            cntl.complete(e, s);
        }
    };
    template <typename Stream, typename Sequence>
    operation(Stream&&, Sequence&&) -> operation<
        std::conditional_t<std::is_lvalue_reference_v<Stream>, Stream&&,
                           std::remove_reference_t<Stream>>,
        std::conditional_t<std::is_lvalue_reference_v<Sequence>, Sequence&&,
                           std::remove_reference_t<Sequence>>>;
};
}  // namespace chx::net::detail

template <typename Stream, typename Sequence, typename CompletionToken>
decltype(auto)
chx::net::async_write_sequence(Stream&& stream, Sequence&& sequence,
                               CompletionToken&& completion_token) {
    using operation_type =
        decltype(detail::async_operation<detail::tags::async_write_seq>::
                     operation(stream, std::forward<Sequence>(sequence)));
    return async_combine<const std::error_code&, std::size_t>(
        stream.get_associated_io_context(),
        std::forward<CompletionToken>(completion_token),
        detail::type_identity<operation_type>{}, stream,
        std::forward<Sequence>(sequence));
}
