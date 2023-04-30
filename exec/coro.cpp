#include <iostream>
#include "../include/chx/net.hpp"

namespace net = chx::net;

net::task<> test() {
    // when using chx/net/coroutine.hpp, this will lead to crash.
    auto await1 = (co_await net::this_context).async_nop(net::use_coro);
    net::ip::tcp::acceptor acceptor(
        co_await net::this_context,
        net::ip::tcp::endpoint(net::ip::tcp::v4(), 10086));

    auto sock = co_await acceptor.async_accept(net::use_coro);
    co_return;
}

int main(void) {
    net::io_context ctx;
    co_spawn(ctx, test());
    ctx.run();
}