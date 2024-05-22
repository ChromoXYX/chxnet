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
        std::tuple<std::string_view, std::variant<std::string, std::string_view,
                                                  std::tuple<std::string>>>
            data{"Response: ", {}};
        static int flag = 0;
        switch (flag) {
        case 0: {
            std::get<1>(data).emplace<0>("string!" + s + "\n");
            break;
        }
        case 1: {
            std::get<1>(data).emplace<1>("fixed string_view! try again!\n");
            break;
        }
        case 2: {
            std::get<1>(data).emplace<2>(
                std::make_tuple("in tuple!" + s + "\n"));
            break;
        }
        }
        flag = (flag + 1) % 3;
        net::async_write_sequence_exactly(
            sock, std::move(data),
            [self = shared_from_this()](const std::error_code& ec,
                                        std::size_t size) {
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
        : acceptor(ctx, net::ip::tcp::endpoint(net::ip::tcp::v4(), 10000)) {}

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
