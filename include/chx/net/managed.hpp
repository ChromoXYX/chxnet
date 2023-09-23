#pragma once

namespace chx::net {
template <typename Stream, typename Container, typename CompletionToken>
decltype(auto) async_write_some_managed(Stream&& stream, Container&& container,
                                        CompletionToken&& completion_token);
}  // namespace chx::net

#include "./impl/async_write_some_managed.ipp"
