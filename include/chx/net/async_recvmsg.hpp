#pragma once

#include <sys/socket.h>

#include "./io_context.hpp"

namespace chx::net {
template <typename Socket, typename CompletionToken>
decltype(auto) async_recvmsg(Socket& socket, msghdr& msghdr,
                             CompletionToken&& completion_token);
}  // namespace chx::net

#include "./impl/async_recvmsg.ipp"
