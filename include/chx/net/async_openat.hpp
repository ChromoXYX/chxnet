#pragma once

#include "./file_descriptor.hpp"

namespace chx::net {
template <typename Pathname, typename CompletionToken>
decltype(auto) async_openat(io_context& ctx, const file_descriptor& dir,
                            Pathname&& pathname, const open_how& how,
                            CompletionToken&& completion_token);
}  // namespace chx::net

#include "./impl/async_openat.ipp"
