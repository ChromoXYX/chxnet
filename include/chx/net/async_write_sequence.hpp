#pragma once

namespace chx::net {
template <typename Stream, typename Sequence, typename CompletionToken>
decltype(auto) async_write_sequence(Stream&& stream, Sequence&& sequence,
                                    CompletionToken&& completion_token);
}

#include "./impl/async_write_sequence.ipp"
