#include <chx/net.hpp>
#include <chx/net/coroutine2.hpp>
#include <iostream>

namespace net = chx::net;

net::task task2(net::semaphore<std::unique_ptr<int>>& q);

static net::cancellation_signal sig;
net::task task(net::semaphore<std::unique_ptr<int>>& q) {
    std::cout << "#1 Wait for semaphore\n";
    std::cout << "#1 Spawn #2\n";
    co_spawn(co_await net::this_context, task2(q),
             [](const std::error_code& e) {
                 std::cout << "#2 Coroutine finished\n";
             });
    std::unique_ptr ptr = co_await q.async_acquire(net::use_coro);
    std::cout << "#1 Get semaphore " << *ptr << " , and cancel #2\n";
    sig.emit();
}

net::task task2(net::semaphore<std::unique_ptr<int>>& q) {
    std::cout << "#2 Wait for semaphore, but #1 would cancel it\n";
    auto [ec, ptr] = co_await q.async_acquire(
        bind_cancellation_signal(sig, net::as_tuple(net::use_coro)));
    std::cout << "#2 ec: " << ec.message() << " and ptr: " << ptr.get() << "\n";
}

int main() {
    net::io_context ctx;
    net::semaphore<std::unique_ptr<int>> queue(ctx);
    co_spawn(ctx, task(queue), [](const std::error_code& e) {
        std::cout << "#1 Coroutine finished\n";
    });
    net::async_timeout(ctx, std::chrono::seconds(1),
                       [&](const std::error_code& e) {
                           std::cout << "Timeout\n";
                           queue.release(new int(42));
                           std::cout << "Semaphore pop\n";
                       });
    ctx.run();
    std::cout << "Remain outstanding tasks = " << ctx.outstanding_tasks()
              << "\n";
    assert(ctx.outstanding_tasks() == 0);
}
