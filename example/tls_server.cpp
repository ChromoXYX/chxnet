#include "../include/chx/net.hpp"
#include "../include/chx/net/ssl/stream.hpp"
#include <iostream>

namespace net = chx::net;

struct session : std::enable_shared_from_this<session> {
    net::ssl::stream<net::ip::tcp::socket> sock;

    session(net::ssl::context& ctx, net::ip::tcp::socket&& s)
        : sock(ctx, std::move(s)) {}

    std::string buf;

    void do_handshake() {
        sock.async_do_handshake(
            [self = shared_from_this()](const std::error_code& ec) {
                if (!ec) {
                    self->do_read();
                } else {
                    std::cout << ec.message() << "\n";
                }
            });
    }

    void do_read() {
        buf.clear();
        net::async_read_until(sock, net::dynamic_buffer(buf), "\r\n\r\n",
                              [self = shared_from_this()](
                                  const std::error_code& e, std::size_t s) {
                                  if (!e) {
                                      self->do_write();
                                  } else {
                                      self->do_shutdown();
                                  }
                              });
    }

    void do_write() {
        static const char* reply =
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: "
            "keep-alive\r\n\r\nHello World";
        sock.async_write_some(net::buffer(reply, strlen(reply)),
                              [self = shared_from_this()](
                                  const std::error_code& e, std::size_t s) {
                                  if (!e) {
                                      self->do_read();
                                  } else {
                                      self->do_shutdown();
                                  }
                              });
    }

    void do_shutdown() {
        sock.async_shutdown(
            [self = shared_from_this()](const std::error_code& e) {});
    }
};

struct server {
    net::ip::tcp::acceptor acceptor;
    net::ssl::context ssl_ctx;

    server(net::io_context& ctx)
        : acceptor(ctx, net::ip::tcp::endpoint(net::ip::tcp::v4(), 4433)),
          ssl_ctx(net::ssl::context::tls_server) {
        ssl_ctx.use_certificate_file("../cert.pem", ssl_ctx.pem);
        ssl_ctx.use_PrivateKey_file("../key.pem", ssl_ctx.pem);
        // ssl_ctx.set_min_proto_version(ssl_ctx.tls1_2);
        // ssl_ctx.set_max_proto_version(ssl_ctx.tls1_2);
        // ssl_ctx.set_options(SSL_OP_ENABLE_KTLS);
    }

    void do_accept() {
        acceptor.async_accept(
            [this](const auto& ec, net::ip::tcp::socket sock) {
                if (!ec) {
                    std::make_shared<session>(ssl_ctx, std::move(sock))
                        ->do_handshake();
                } else {
                    std::cerr << ec.message() << "\n";
                }
                do_accept();
            });
    }
};

int main(void) {
    signal(SIGPIPE, SIG_IGN);

    net::io_context ctx;

    net::signal sig(ctx);
    sig.add(SIGINT);
    sig.async_wait([&](const std::error_code&, int) { ctx.stop(); });

    server s(ctx);
    s.do_accept();
    ctx.run();
}