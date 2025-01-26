#include <chx/net/coroutine2.hpp>
#include <chx/net/basic_fixed_timer.hpp>
#include <chx/net/detached.hpp>
#include <iostream>

namespace net = chx::net;

struct my_tag {};
template <> struct net::detail::async_operation<my_tag> {
    io_context::task_t* operator()(io_context& ctx) {
        io_context::task_t* t = ctx.acquire();
        t->__M_persist = true;
        return t;
    }
    void release(io_context::task_t* t) {
        t->get_associated_io_context().release(t);
    }
};

template <typename CompletionToken>
decltype(auto) prep_reusable_impl(net::io_context::task_t* t,
                                  CompletionToken&& completion_token) {
    return net::detail::async_token_init(
        t->__M_token.emplace(net::detail::async_token_generate(
            t,
            [](auto& token, net::io_context::task_t* t) -> int {
                token(t->__M_ec);
                return 0;
            },
            completion_token)),
        completion_token);
}
template <typename CompletionToken>
decltype(auto) prep_reusable(net::io_context::task_t* t,
                             CompletionToken&& completion_token) {
    return prep_reusable_impl(
        t, net::detail::async_token_bind<const std::error_code&>(
               std::forward<CompletionToken>(completion_token)));
}

namespace {
net::io_context::task_t* t = nullptr;
net::fixed_timer* timer = nullptr;
int counter = 0;

void wait_loop() {
    timer->async_register(
        std::chrono::seconds(1), [](const std::error_code& e) {
            std::cout << "Timer triggered\n";
            if (++counter < 3) {
                t->__M_token(t);
                wait_loop();
            } else {
                std::cout << "Now we will release task that coro waiting "
                             "at\nCoro should wait forever\n";
                net::detail::async_operation<my_tag>().release(t);
            }
        });
}
}  // namespace

net::task task() {
    t = net::detail::async_operation<my_tag>()(co_await net::this_context);
    auto a = prep_reusable(t, net::use_multishot_coro);
    wait_loop();

    try {
        for (;;) {
            std::cout << "Start wait\n";
            std::error_code e = co_await a;
            std::cout << "End wait\n";
        }
    } catch (const std::exception& e) {
        std::cout << "Loop Exit, exception: " << e.what() << "\n";
    }
}
void example() {}

int main() {
    net::io_context ctx;
    net::fixed_timer timer(ctx);
    ::timer = &timer;
    co_spawn(ctx, task(),
             [](const std::error_code&) { std::cout << "Coroutine exit\n"; });
    ctx.run();
}