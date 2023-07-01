#include <iostream>
#include "../include/chx/net.hpp"

int main(void) {
    chx::net::io_context ctx;
    chx::net::ktimer timer(ctx);
    timer.expired_after(std::chrono::seconds(5));
    timer.async_wait([](const auto& e) { std::cout << e.message() << "\n"; });
    ctx.run();
}
