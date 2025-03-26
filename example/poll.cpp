#include <chx/net/io_context.hpp>
#include <iostream>

namespace net = chx::net;

int main() {
    net::io_context ctx;
    ctx.post([i = 0, &ctx]() mutable -> int {
        std::cout << "No. " << (++i) << "\n";
        ctx.interrupt();
        return i != 3;
    });
    ctx.interrupt();
    ctx.run();
    return 0;
}
