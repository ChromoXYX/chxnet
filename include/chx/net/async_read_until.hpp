#pragma once

#include "./io_context.hpp"

namespace chx::net {
template <typename Stream, typename DynamicBuffer, typename StopCondition,
          typename CompletionToken>
decltype(auto) async_read_until(Stream& stream, DynamicBuffer&& dynamic_buffer,
                                StopCondition&& stop_condition,
                                CompletionToken&& completion_token);
}  // namespace chx::net

#include "./impl/async_read_until.ipp"
