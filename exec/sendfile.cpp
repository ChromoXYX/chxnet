#include "../include/chx/net.hpp"
#include <iostream>

namespace net = chx::net;

struct server {
    net::ip::tcp::acceptor acceptor;
    net::ip::tcp::socket socket;

    server(net::io_context& ctx)
        : acceptor(ctx, net::ip::tcp::endpoint(net::ip::tcp::v4(), 10001)),
          socket(ctx) {}

    void do_accept() {
        acceptor.async_accept(
            [this](const std::error_code& e, net::ip::tcp::socket sock) {
                if (!e) {
                    socket = std::move(sock);
                    do_sendfile();
                } else {
                    std::cerr << "failed to accept:\t" << e.message() << "\n";
                }
            });
    }

    void do_sendfile() {
        net::async_sendfile(
            net::file(socket.get_associated_io_context(), "configure.ac"),
            socket, 65535, [this](const std::error_code& e, std::size_t s) {
                if (!e) {
                    std::cout << "send\t" << s << "\n";
                } else {
                    std::cerr << "failed to send:\t" << e.message() << "\n";
                }
            });
    }
};

net::task<> work() {
    net::ip::tcp::acceptor acceptor(
        co_await net::this_context,
        net::ip::tcp::endpoint(net::ip::tcp::v4(), 10000));
    auto socket = co_await acceptor.async_accept(net::use_coro);

    net::file f(co_await net::this_context, "configure.ac");
    std::size_t sz =
        co_await net::async_sendfile(f, socket, 65535, net::use_coro);
    std::cout << "send\t" << sz << "\tvia coro\n";
}

int main(void) {
    net::io_context ctx;
    co_spawn(ctx, work(), net::detached);
    ctx.run();
}
