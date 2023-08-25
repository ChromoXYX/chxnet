#pragma once

#include "./impl/async_write_sequence.ipp"

namespace chx::net {
template <typename Stream, typename Sequence, typename CompletionToken>
decltype(auto) async_read_sequence(Stream& stream, Sequence&& sequence,
                                   CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::async_write_seq>()(
        &stream.get_associated_io_context(),
        detail::async_operation<detail::tags::async_write_seq>::write_seq1(
            detail::async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)),
            std::forward<Sequence>(sequence), stream.native_handler(),
            std::false_type{}));
}
}  // namespace chx::net
