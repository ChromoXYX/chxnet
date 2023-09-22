#pragma once

namespace chx::net {
template <typename Stream, typename Container, typename CompletionToken>
decltype(auto) async_write_some_exactly(Stream&& stream, Container&& container,
                                        CompletionToken&& completion_token);
}

#include "./impl/async_write_some_exactly.ipp"
