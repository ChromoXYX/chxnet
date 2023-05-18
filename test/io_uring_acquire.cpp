#include "../include/chx/net.hpp"

namespace net = chx::net;

namespace chx::net::detail {
namespace tags {
struct test_acquire {};
}  // namespace tags

template <> struct async_operation<tags::test_acquire> {
    void operator()(io_context* ctx) {
        auto [sqe, task] = ctx->get();
        io_uring_prep_nop(sqe);
        task->__M_token.emplace([](auto...) -> int { return 0; });
    }
};
}  // namespace chx::net::detail

int main(void) {
    net::io_context ctx;
    for (int i = 0; i < 10000000; ++i) {
        chx::net::detail::async_operation<
            chx::net::detail::tags::test_acquire>()(&ctx);
    }
    return 0;
}
