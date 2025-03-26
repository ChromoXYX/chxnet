#include <chx/net/ip/resolver.hpp>
#include <chx/net/tcp.hpp>
#include <iostream>

namespace net = chx::net;

namespace {
auto callback = [](const std::error_code&, net::ip::addrinfo_list list) {
    static int cnt = 0;
    std::cout << "For #" << ++cnt << "\n";
    for (auto& item : list) {
        std::cout << net::ip::tcp::endpoint::make_endpoint(item.ai_addr)
                         .address()
                         .to_string()
                  << "\n";
    }
    std::cout << "\n";
};
}

int main() {
    net::io_context ctx;
    net::ip::resolver resolver(ctx, 20);
    resolver.async_resolve("www.baidu.com", callback);
    resolver.async_resolve("www.google.com", callback);
    resolver.async_resolve("www.cloudflare.com", callback);
    resolver.async_resolve("www.bilibili.com", callback);
    resolver.async_resolve("en.cppreference.com", callback);
    resolver.async_resolve("www.github.com", callback);
    resolver.async_resolve("www.kernel.org", callback);
    ctx.run();
    resolver.cancel();
}
