#include "../include/chx/net.hpp"
#include <iostream>

namespace net = chx::net;

int cwd = -1;

net::task work() {
    net::ip::tcp::acceptor acceptor(
        co_await net::this_context,
        net::ip::tcp::endpoint(net::ip::tcp::v4(), 10000));
    auto socket = co_await acceptor.async_accept(net::use_coro);

    net::file dir(co_await net::this_context, dup(cwd));
    net::file f(co_await net::this_context);
    co_await f.async_openat(dir, "configure.ac", net::use_coro);
    std::cout << "sent\t"
              << (co_await net::async_sendfile(f, socket, 65535, net::use_coro))
              << "\n";
}

int main(void) {
    cwd = open(".", O_DIRECTORY);
    assert(cwd > 0);

    net::io_context ctx;
    co_spawn(ctx, work(), net::detached);
    ctx.run();

    close(cwd);
}
