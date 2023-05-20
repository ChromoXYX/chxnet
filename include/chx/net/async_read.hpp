#pragma once

#include "./dynamic_buffer.hpp"

namespace chx::net {
template <typename Stream, typename DynamicBuffer, typename CompletionToken>
decltype(auto) async_read(Stream& stream, DynamicBuffer&& dynamic_buffer,
                          CompletionToken&& completion_token);
}

#include "./impl/async_read.ipp"
