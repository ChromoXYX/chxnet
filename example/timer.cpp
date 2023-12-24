#include "../include/chx/net.hpp"
#include <iostream>
#include <functional>

namespace net = chx::net;

static net::io_context ctx;
static net::fixed_timer global_timer(ctx);
static net::fixed_timeout_timer ftt(ctx), timer2(ctx);

auto start = std::chrono::system_clock::now();

auto current() { return std::chrono::system_clock::now(); }
void print_current() {
    std::cout << "["
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     current() - start)
              << "]";
}

net::task task1() {
    print_current();
    std::cout << "Task1 will test fixed_timer\n";
    print_current();
    std::cout << "Task1: i should sleep for 2s\n";
    co_await global_timer.async_register(std::chrono::seconds(2),
                                         net::use_coro);
    print_current();
    std::cout << "Task1: hey, you finally wake. now sleep for 5s, but "
                 "meanwhile cancel "
                 "the task\n";
    net::cancellation_signal signal;
    auto awaitable1 = global_timer.async_register(
        std::chrono::seconds(5),
        bind_cancellation_signal(signal, net::as_tuple(net::use_coro)));
    signal.emit();
    print_current();
    std::cout << "Task1: now what? "
              << std::get<0>(co_await awaitable1).message() << "\n";
    print_current();
    std::cout << "Task1: let's sleep for 2s, but change to 3s right after\n";
    auto awaitable2 = global_timer.async_register(
        std::chrono::seconds(2),
        bind_cancellation_signal(signal, net::as_tuple(net::use_coro)));
    auto* ptr = static_cast<net::fixed_timer_cancellation<net::fixed_timer>*>(
        signal.get());
    assert(ptr && ptr->valid());
    ptr->update(std::chrono::seconds(3));
    co_await awaitable2;
    print_current();
    std::cout << "Task1: success"
              << "\n";
}

net::task task2() {
    print_current();
    std::cout << "Task2 will test fixed_timeout_timer\n";
    print_current();
    std::cout << "Task2: i want a 1.5s nap\n";
    co_await ftt.async_register(std::chrono::milliseconds(1500), net::use_coro);
    print_current();
    std::cout << "Task2: then i wake. try working for 3s, but lose my "
                 "attention after 1s\n";
    net::cancellation_signal signal;
    auto awaitable1 =
        ftt.async_register(std::chrono::seconds(3),
                           bind_cancellation_signal(signal, net::use_coro));
    auto* ptr =
        static_cast<net::fixed_timer_cancellation<net::fixed_timeout_timer>*>(
            signal.get());
    assert(ptr && ptr->valid());
    ptr->update(std::chrono::seconds(1));
    co_await awaitable1;
    print_current();
    std::cout
        << "Task2: back to work! try to work for 5s, but give up after 2s\n";
    auto awaitable2 = ftt.async_register(
        std::chrono::seconds(5), chx::net::bind_cancellation_signal(
                                     signal, net::as_tuple(net::use_coro)));
    co_await ftt.async_register(std::chrono::seconds(2), net::use_coro);
    signal.emit();
    auto rtp = co_await awaitable2;
    print_current();
    std::cout << "Task2: now what? " << std::get<0>(rtp).message() << "\n";
}

net::task task3() {
    print_current();
    std::cout << "Task3 will test cancellation of timer\n";
    print_current();
    std::cout << "Task3: i will sleep for 2s\n";
    co_await timer2.async_register(std::chrono::seconds(2), net::use_coro);
    print_current();
    std::cout
        << "Task3: after, i will cancel timer2, but still try to wait for it\n";
    co_await (co_await net::this_context).async_nop(net::use_coro);
    co_await timer2.get_cancellation()->async_remove(net::use_coro);
    auto awaitable =
        timer2.async_register(std::chrono::seconds(2), net::use_coro);
    co_await awaitable;
}

void watch_dog(const std::error_code& e, net::ktimer& ktimer) {
    if (!e) {
        ktimer.expired_after(std::chrono::milliseconds(200));
        print_current();
        std::cout << "Watch Dog: outstanding tasks: " << ctx.outstanding_tasks()
                  << "\n";
        ktimer.async_wait(
            std::bind(watch_dog, std::placeholders::_1, std::ref(ktimer)));
    }
}

int main() {
    global_timer.set_interval(std::chrono::milliseconds(200));
    ftt.set_interval(std::chrono::milliseconds(200));
    timer2.set_interval(std::chrono::milliseconds(200));
    global_timer.listen();
    ftt.listen();
    timer2.listen();

    std::cout << "press Ctrl+C to exit.\n";
    std::cout
        << "after everything has settled down, number of outstanding "
           "tasks should be 6.\n"
        << "\t2 running timers = 2 tasks\n\t1 hanging coroutine = 2 "
           "tasks\n\t1 watch dog timer = 1 task\n\t1 signal_set = 1 task\n\n";

    co_spawn(ctx, task1(), net::detached);
    co_spawn(ctx, task2(), net::detached);
    co_spawn(ctx, task3(), net::detached);

    net::ktimer ktimer(ctx);
    watch_dog(std::error_code{}, ktimer);

    net::signal signal_set(ctx);
    signal_set.add(SIGINT);
    signal_set.async_wait([&](const std::error_code& e, int) {
        std::cout << "exit...\n";
        ctx.stop();
    });

    ctx.run();
}
