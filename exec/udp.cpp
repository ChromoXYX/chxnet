#include <iostream>

#include "../include/chx/net.hpp"

namespace net = chx::net;

struct session {
    net::ip::udp::socket sock;
    std::string s;

    session(net::io_context& ctx) : sock(ctx, net::ip::udp::v4()) {}

    void start() {
        sock.async_connect(
            {net::ip::address_v4::from_string("127.0.0.1"), 40000},
            [this](const std::error_code& ec) {
                if (!ec) {
                    do_write();
                } else {
                    std::cerr << "failed to connect: " << ec.message() << "\n";
                }
            });
    }

    void do_write() {
        static const char* msg = "hello world";
        sock.async_write(
            net::buffer(msg, 11), [](const std::error_code& e, std::size_t s) {
                if (!e) {
                    std::cout << "write successful\n";
                } else {
                    std::cout << "failed to write: " << e.message() << "\n";
                }
            });
    }

    void do_read() {
        s.clear();
        sock.async_read_until(net::dynamic_buffer(s), "EOL",
                              [this](const std::error_code& e, std::size_t sz) {
                                  if (!e) {
                                      s.resize(sz - 3);
                                      std::cout << "recv: " << s << "\n";
                                  } else {
                                      std::cerr
                                          << "failed to read: " << e.message()
                                          << "\n";
                                  }
                              });
    }

    void do_send() {
        static const char* msg = "hello world";
        sock.async_sendto(
            net::buffer(msg, 11),
            {net::ip::address_v4::from_string("127.0.0.1"), 40000},
            [](const std::error_code& e, std::size_t sz) {
                if (!e) {
                    std::cout << "sendto successful\n";
                } else {
                    std::cerr << "failed to sendto: " << e.message() << "\n";
                }
            });
    }
};

int main() {
    net::io_context ctx;
    session ses(ctx);
    ses.do_send();
    ctx.run();
}
