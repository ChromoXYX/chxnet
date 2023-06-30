#define CHXNET_ENABLE_CORO_WHEN_ANY 1

#include <iostream>
#include "../include/chx/net.hpp"
#include "../include/chx/net/detached.hpp"

namespace net = chx::net;

net::task<> test() {
    // when using chx/net/coroutine.hpp, this coro will lead to crash.
    {
        net::ip::tcp::acceptor acceptor1(
            co_await net::this_context,
            net::ip::tcp::endpoint(net::ip::tcp::v4(), 10086));
        net::ip::tcp::acceptor acceptor2(
            co_await net::this_context,
            net::ip::tcp::endpoint(net::ip::tcp::v4(), 10087));
        auto a1 = acceptor1.async_accept(net::use_coro);
        auto a2 = acceptor2.async_accept(net::as_tuple(net::use_coro));
        acceptor2.close();
        auto [val, idx] = co_await net::when_any(a1, a2);
        std::cout << val.index() << "\n";
    }
    auto& this_ctx = co_await net::this_context;
    {
        auto [val, idx] =
            co_await net::when_any(this_ctx.async_nop(net::use_coro),
                                   this_ctx.async_nop(net::use_coro));
        std::cout << val.index() << "\n";
    }
}

int main(void) {
    net::io_context ctx;
    co_spawn(ctx, test(), net::detached);
    ctx.run();
}