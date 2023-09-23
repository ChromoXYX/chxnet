#pragma once

namespace chx::net {
namespace detail {
struct no_short_write {};
}  // namespace detail

template <typename Stream, typename Sequence, typename CompletionToken>
decltype(auto) async_write_sequence_exactly(Stream&& stream,
                                            Sequence&& sequence,
                                            CompletionToken&& completion_token);
}  // namespace chx::net

#include "./impl/async_write_sequence_exactly.ipp"
