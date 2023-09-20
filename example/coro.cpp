#define CHXNET_ENABLE_CORO_WHEN_ANY 1

#include <iostream>
#include "../include/chx/net.hpp"
#include "../include/chx/net/detached.hpp"

namespace net = chx::net;

net::task test() {
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
    co_return;
}

net::future<int> chain3() {
    net::io_context& ctx = co_await net::this_context;
    std::cout << 16 << "\n";
    co_await ctx.async_nop(net::use_coro);
    std::cout << 17 << "\n";
    co_await ctx.async_nop(net::use_coro);
    std::cout << 18 << "\n";
    co_return 19;
}

net::future<> chain2() {
    net::io_context& ctx = co_await net::this_context;
    std::cout << 14 << "\n";
    co_await ctx.async_nop(net::use_coro);
    std::cout << 15 << "\n";
    co_await ctx.async_nop(net::use_coro);
    std::cout << co_await chain3() << "\n";
    co_return;
}

net::nop_future<int> norm() {
    std::cout << "this is a normal function\n";
    return {42};
}

net::task chain1() {
    net::io_context& ctx = co_await net::this_context;
    std::cout << 11 << "\n";
    co_await ctx.async_nop(net::use_coro);
    std::cout << 12 << "\n";
    co_await ctx.async_nop(net::use_coro);
    std::cout << 13 << "\n";
    co_await chain2();
    std::cout << "\t and it's return value is " << co_await norm() << "\n";
}

int main(void) {
    net::io_context ctx;
    co_spawn(ctx, test(), net::detached);
    co_spawn(ctx, chain1(), net::detached);
    ctx.run();
}