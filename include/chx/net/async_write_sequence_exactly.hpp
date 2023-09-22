#pragma once

namespace chx::net {
template <typename Stream, typename Sequence, typename CompletionToken>
decltype(auto)
async_write_sequence_exactly(Stream&& stream, Sequence&& sequence,
                                     CompletionToken&& completion_token);
}

#include "./impl/async_write_sequence_exactly.ipp"
