#include "../include/chx/net.hpp"
#include <iostream>

chx::net::fixed_timer* global_timer;

chx::net::task task() {
    std::cout << "start coroutine\n\tsleep for 3s\n";
    auto begin = std::chrono::system_clock::now();
    co_await global_timer->async_register(std::chrono::seconds(3),
                                          chx::net::use_coro);
    std::cout << "hey you, you finally wake, after "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::system_clock::now() - begin)
                     .count()
              << "ms\n";
}

int main() {
    chx::net::io_context ctx;
    chx::net::fixed_timer timer(ctx);
    global_timer = &timer;

    timer.set_interval(std::chrono::milliseconds(200));
    chx::net::cancellation_signal signal;
    timer.async_register(
        std::chrono::seconds(2),
        timer.bind_cancellation_signal(signal, [](const std::error_code& e) {
            std::cout << "1 for 2s " << e.message() << "\n";
        }));
    timer.async_register(std::chrono::seconds(4),
                         [&signal](const std::error_code& e) mutable {
                             std::cout << "2 for 4s " << e.message() << "\n";
                             signal.emit();
                         });
    co_spawn(ctx, task(), chx::net::detached);
    std::cout << "timer interval is " << timer.get_interval() << "\n";
    timer.listen();
    ctx.run();
}