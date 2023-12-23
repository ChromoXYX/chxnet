#include "../include/chx/net.hpp"
#include <iostream>

chx::net::fixed_timer* global_timer;
chx::net::fixed_timeout_timer* ftt;

chx::net::task task() {
    std::cout << "task1: start coroutine\n\tsleep for 3s via fixed_timer\n";
    auto begin = std::chrono::system_clock::now();
    co_await global_timer->async_register(std::chrono::seconds(3),
                                          chx::net::use_coro);
    std::cout << "task1: fixed_timer: hey you, you finally wake, after "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::system_clock::now() - begin)
                     .count()
              << "ms\n";
}

chx::net::task task2() {
    std::cout << "task2: start coroutine\n\tsleep for 1s via timeout\n";
    chx::net::timeout_handler h;
    auto awaitable = async_timeout(
        co_await chx::net::this_context, std::chrono::seconds(1),
        bind_timeout_handler(h, chx::net::as_tuple(chx::net::use_coro)));
    std::cout << "task2: i think sleep 5s is better\n";
    co_await h.async_update(std::chrono::seconds(5), chx::net::use_coro);
    std::cout
        << "task2: oops, 5s may be way too long, let's cancel the timeout!\n";
    co_await h.async_remove(chx::net::use_coro);
    std::cout << "task2: timeout result "
              << std::get<0>(co_await awaitable).message() << "\n";
}

chx::net::task task3() {
    std::cout << "task3: start fixed_timeout_timer\n";
    std::cout << "task3: now sleep for 1s\n";
    co_await ftt->async_register(std::chrono::seconds(1), chx::net::use_coro);
    std::cout << "task3: now task3 sleep for 1.5s, but cancel it right after\n";
    chx::net::cancellation_signal signal;
    auto awaitable = ftt->async_register(
        std::chrono::milliseconds(1500),
        bind_cancellation_signal(signal,
                                 chx::net::as_tuple(chx::net::use_coro)));
    signal.emit();
    std::cout << "task3: now what? "
              << std::get<0>(co_await awaitable).message()
              << "\ntask3: now task3 will sleep for 1s, but we cancel the "
                 "timeout_timer\n";
    auto awaitable2 =
        ftt->async_register(std::chrono::seconds(5), chx::net::use_coro);
    // pass a round, so that fixed_timeout_timer can update the handler
    co_await (co_await chx::net::this_context).async_nop(chx::net::use_coro);
    co_await ftt->get_timeout_handler().async_remove(chx::net::use_coro);
    co_await awaitable2;
    std::cout << "task3: you should never see this!\n";
}

int main() {
    chx::net::io_context ctx;
    chx::net::signal s(ctx);
    s.add(SIGINT);
    s.async_wait([&ctx](const std::error_code& e, int s) {
        ctx.stop();
        std::cout << "exit...\n";
    });
    std::cout << "press Ctrl+C to force exit\n";
    chx::net::fixed_timer timer(ctx);
    global_timer = &timer;
    chx::net::fixed_timeout_timer fixed_timeout_timer(ctx);
    fixed_timeout_timer.set_interval(std::chrono::milliseconds(500));
    ftt = &fixed_timeout_timer;

    timer.set_interval(std::chrono::milliseconds(200));
    chx::net::cancellation_signal signal;
    timer.async_register(
        std::chrono::seconds(2),
        timer.bind_cancellation_signal(signal, [](const std::error_code& e) {
            std::cout << "main: 1 for 2s " << e.message() << "\n";
        }));
    timer.async_register(std::chrono::seconds(4),
                         [&signal](const std::error_code& e) mutable {
                             std::cout << "main: 2 for 4s " << e.message() << "\n";
                             signal.emit();
                         });
    co_spawn(ctx, task(), chx::net::detached);
    std::cout << "main: timer interval is " << timer.get_interval() << "\n";
    timer.listen();

    chx::net::timeout_handler h;
    async_timeout(ctx, std::chrono::seconds(1),
                  bind_timeout_handler(h, [](const std::error_code& e) {
                      std::cout << "main: wake from timeout: " << e.message() << "\n";
                  }));
    h.async_update(std::chrono::seconds(5), [](const std::error_code& e) {
        std::cout << "main: what now? " << e.message() << "\n";
    });
    h.async_remove([](const std::error_code& e) {
        std::cout << "main: cancel timeout! " << e.message() << "\n";
    });

    fixed_timeout_timer.listen();

    co_spawn(ctx, task2(), chx::net::detached);
    co_spawn(ctx, task3(), chx::net::detached);

    ctx.run();
}