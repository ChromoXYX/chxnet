// a simple echo example

#include <iostream>

#include "../include/chx/net.hpp"

namespace net = chx::net;

struct session : std::enable_shared_from_this<session> {
    net::ip::tcp::socket sock;
    std::string s;

    session(net::ip::tcp::socket&& s) : sock(std::move(s)) {}

    void do_read() {
        s.clear();
        net::async_read_until(sock, net::dynamic_buffer(s), "EOL",
                              [self = shared_from_this()](
                                  const std::error_code& ec, std::size_t size) {
                                  if (!ec) {
                                      self->s.resize(size - 3);
                                      self->s += '\n';
                                      self->do_write();
                                  } else {
                                      std::cerr << "encountered "
                                                << ec.message() << "\n";
                                  }
                              });
    }

    void do_write() {
        sock.async_write_some(
            net::buffer(s), [self = shared_from_this()](
                                const std::error_code& ec, std::size_t size) {
                if (!ec) {
                    self->do_read();
                } else {
                    std::cerr << "encountered " << ec.message() << "\n";
                }
            });
    }
};

struct server {
    net::ip::tcp::acceptor acceptor;

    server(net::io_context& ctx)
        : acceptor(ctx, net::ip::tcp::endpoint(net::ip::tcp::v4(), 12345)) {}

    void do_accept() {
        acceptor.async_accept(
            [this](const std::error_code& ec, net::ip::tcp::socket sock) {
                if (!ec) {
                    std::make_shared<session>(std::move(sock))->do_read();
                } else {
                    std::cerr << "encountered " << ec.message() << "\n";
                    std::cerr << "still listening...\n";
                }
                do_accept();
            });
    }
};

int main(void) {
    net::io_context ctx;
    server s(ctx);
    s.do_accept();
    ctx.run();
}
