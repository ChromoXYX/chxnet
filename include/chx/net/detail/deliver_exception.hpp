#pragma once

#include "../io_context.hpp"

namespace chx::net::detail {
inline void deliver_exception(io_context* ctx, std::exception_ptr ex) {
    ctx->async_nop(
        [ex](const std::error_code& ec) { std::rethrow_exception(ex); });
}
}  // namespace chx::net::detail