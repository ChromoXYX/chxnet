// simple http server

#include <iostream>
#include <llhttp.h>
#include <vector>

#include "../include/chx/net.hpp"

namespace net = chx::net;

struct http_state_machine : std::enable_shared_from_this<http_state_machine> {
    static int buffer_consume(llhttp_t* p, const char* b, std::size_t s) {
        auto* self = static_cast<http_state_machine*>(p->data);
        self->buffer.append(b, s);
        return 0;
    }

    http_state_machine(const http_state_machine&) = delete;

    http_state_machine(net::ip::tcp::socket&& s) : sock(std::move(s)) {
        llhttp_settings_init(&settings);
        settings.on_header_field = buffer_consume;
        settings.on_header_value = buffer_consume;
        settings.on_url = buffer_consume;

        settings.on_header_field_complete = +[](llhttp_t* p) -> int {
            auto* self = static_cast<http_state_machine*>(p->data);
            self->headers.emplace_back(std::move(self->buffer), std::string());
            self->buffer.clear();
            return 0;
        };
        settings.on_header_value_complete = +[](llhttp_t* p) -> int {
            auto* self = static_cast<http_state_machine*>(p->data);
            if (self->headers.empty()) {
                return -1;
            } else {
                self->headers.back().second = std::move(self->buffer);
                self->buffer.clear();
                return 0;
            }
        };
        settings.on_url_complete = +[](llhttp_t* p) -> int {
            auto* self = static_cast<http_state_machine*>(p->data);
            self->url = std::move(self->buffer);
            self->buffer.clear();
            return 0;
        };
        settings.on_message_complete = +[](llhttp_t* p) -> int {
            auto* self = static_cast<http_state_machine*>(p->data);
            self->complete();
            return 0;
        };
        llhttp_init(&parser, HTTP_REQUEST, &settings);
        parser.data = this;
    }

    llhttp_t parser = {};
    llhttp_settings_t settings = {};

    std::string buffer;
    bool completed = false;
    std::string url;
    std::vector<std::pair<std::string, std::string>> headers;

    void consume() {
        net_buf.clear();
        sock.async_read_until(
            net::dynamic_buffer(net_buf), "\r\n",
            [self = shared_from_this()](const std::error_code& e,
                                        std::size_t s) {
                if (!e) {
                    llhttp_errno_t r =
                        llhttp_execute(&self->parser, self->net_buf.data(),
                                       self->net_buf.size());
                    if (r == HPE_OK && !self->completed) {
                        self->consume();
                    } else if (r != HPE_OK) {
                        std::cerr << "http failed: " << llhttp_errno_name(r)
                                  << "\n";
                    }
                } else {
                    std::cerr << "encountered error: " << e.message() << "\n";
                }
            });
    }
    void complete() {
        completed = true;

        resp[0] =
            "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: ";
        for (auto& [k, v] : headers) {
            resp[1].append(k);
            resp[1].append(": ");
            resp[1].append(v);
            resp[1].append("\n");
        }
        resp[0].append(std::to_string(resp[1].size()));
        resp[0].append("\r\n\r\n");

        static char response[] =
            "HTTP/1.1 200 OK\r\nContent-Length: "
            "11\r\nConnection: keep-alive\r\n\r\nHello World";
        sock.async_write(resp, [self = shared_from_this()](
                                   const std::error_code& e, std::size_t s) {
            self->resp = {};
            self->headers.clear();
            if (e) {
                std::cerr << "failed to response\n";
            } else {
                llhttp_reset(&self->parser);
                self->consume();
            }
        });
    }

    net::ip::tcp::socket sock;
    std::string net_buf;

    std::array<std::string, 2> resp;
};

struct server {
    net::ip::tcp::acceptor acceptor;

    server(net::io_context& ctx)
        : acceptor(ctx, net::ip::tcp::endpoint(net::ip::tcp::v4(), 10086)) {}

    void do_accept() {
        acceptor.async_accept(
            [this](const std::error_code& e, net::ip::tcp::socket sock) {
                if (!e) {
                    std::make_shared<http_state_machine>(std::move(sock))
                        ->consume();
                } else {
                    std::cerr << "failed to accept\n";
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
