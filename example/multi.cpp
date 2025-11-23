#include <chx/net.hpp>
#include <sys/poll.h>

namespace net = chx::net;

struct session : std::enable_shared_from_this<session> {
    net::ip::tcp::socket socket;
    net::cancellation_signal signal;

    char buffer[64] = {};

    session(net::ip::tcp::socket&& sock) : socket(std::move(sock)) {}

    void do_poll() {
        socket.async_poll_multi(
            POLLIN,
            bind_cancellation_signal(
                signal, [self = shared_from_this()](const std::error_code& ec,
                                                    auto res) {
                    auto [revents, next] = res;
                    printf("Poll: %s, Next %d, Event %d\n",
                           ec.message().c_str(), next, revents);
                    if (!ec && (revents & POLLIN)) {
                        self->socket.async_read_some(
                            net::buffer(self->buffer),
                            [self](const std::error_code& e, std::size_t s) {
                                printf("Read: %s, %zu byte(s)\n",
                                       e.message().c_str(), s);
                                printf("cancel poll\n");
                                self->signal.emit();
                            });
                    }
                }));
    }
};

struct server {
    net::ip::tcp::acceptor acceptor;

    server(net::io_context& ctx)
        : acceptor(ctx,
                   {net::ip::address_v4::from_string("127.0.0.1"), 12345}) {
        do_accept();
    }

    void do_accept() {
        acceptor.async_accept(
            [this](const std::error_code& e, net::ip::tcp::socket sock) {
                printf("Accept: %s\n", e.message().c_str());
                if (!e) {
                    std::make_shared<session>(std::move(sock))->do_poll();
                }
            });
    }
};

int main() {
    net::io_context ctx;
    net::ip::tcp::socket socket(ctx, net::ip::tcp::v4());
    server srv(ctx);

    net::ip::tcp::socket client(ctx, net::ip::tcp::v4());
    client.async_connect({net::ip::address::from_string("127.0.0.1"), 12345},
                         [&](const std::error_code& e) {
                             printf("Client connect: %s\n",
                                    e.message().c_str());
                             if (!e) {
                                 net::async_write_sequence_exactly(
                                     client, std::string{"a"},
                                     [&](const std::error_code&, std::size_t) {
                                         client.shutdown(client.shutdown_write);
                                     });
                             }
                         });
    ctx.run();
}