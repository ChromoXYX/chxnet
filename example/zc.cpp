#include <chx/net.hpp>
#include <chx/net/tcp.hpp>
#include <chx/net/coroutine2.hpp>
#include <chx/net/async_sendmsg.hpp>
#include <iostream>
#include <chx/net/type_traits/is_container.hpp>
#include <chx/net/type_traits/is_sequence.hpp>

namespace net = chx::net;

net::task<> server() {
    net::io_context& ctx = co_await net::this_context;
    net::ip::tcp::acceptor acceptor(
        ctx, {net::ip::address::from_string("127.0.0.1"), 8888});
    for (;;) {
        std::shared_ptr sock = std::make_shared<net::ip::tcp::socket>(
            co_await acceptor.async_accept(net::use_coro));
        std::vector<std::string> message = {"Hello, ", "World!", "\n"};
        net::async_sendmsg_zero_copy_exactly(
            ctx, *sock, std::move(message),
            [sock](const std::error_code& e, std::size_t s) {
                std::cout << e.message() << ", " << s << " bytes sent\n";
            });
    }
    co_return;
}

int main() {
    net::io_context ctx;
    co_spawn(ctx, server(), net::detached);
    ctx.run();
}
