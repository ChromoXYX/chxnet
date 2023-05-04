#include <iostream>
#include "../include/chx/net.hpp"
#include "../include/chx/net/detached.hpp"

namespace net = chx::net;

net::task<> test() {
    // when using chx/net/coroutine.hpp, this coro will lead to crash.
    net::ip::tcp::acceptor acceptor1(
        co_await net::this_context,
        net::ip::tcp::endpoint(net::ip::tcp::v4(), 10086));
    net::ip::tcp::acceptor acceptor2(
        co_await net::this_context,
        net::ip::tcp::endpoint(net::ip::tcp::v4(), 10087));
    auto a1 = acceptor1.async_accept(net::use_coro);
    auto a2 = acceptor2.async_accept(net::as_tuple(net::use_coro));
    acceptor2.close();
    auto [ec, val] = co_await (a1 || a2);
    std::cout << ec.message() << "\n";
    std::cout << val.index() << "\n";
    if (val.index() == 2) {
        std::cout << std::get<0>(std::get<2>(val)).message() << "\n";
    }
}

int main(void) {
    net::io_context ctx;
    co_spawn(ctx, test(), net::detached);
    ctx.run();
}