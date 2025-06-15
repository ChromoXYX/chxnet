#pragma once

#include <sys/socket.h>

#include "./io_context.hpp"

namespace chx::net {
template <typename Socket, typename CompletionToken>
decltype(auto) async_sendmsg(io_context& ctx, Socket& socket,
                             const msghdr& msghdr,
                             CompletionToken&& completion_token);

template <typename Socket, typename CompletionToken>
decltype(auto) async_sendmsg_zero_copy(io_context& ctx, Socket& socket,
                                       const msghdr& msghdr,
                                       CompletionToken&& completion_token);

template <typename Socket, typename Sequence, typename CompletionToken>
decltype(auto)
async_sendmsg_zero_copy_exactly(io_context& ctx, Socket& socket,
                                Sequence&& sequence,
                                CompletionToken&& completion_token);
}  // namespace chx::net

#include "./impl/async_sendmsg.ipp"
