#include <chx/net.hpp>
#include <chx/net/coroutine2.hpp>
#include <chx/net/detail/proxy.hpp>

namespace net = chx::net;

net::task<> server(net::semaphore& sem) {
    net::io_context& ctx = co_await net::this_context;
    net::ip::tcp::acceptor acceptor(
        ctx, {net::ip::address::from_string("127.0.0.1"), 20000});
    sem.release();
    auto sock = co_await acceptor.async_accept(net::use_coro);
    static char buffer[10240] = {};
    co_await sock.async_write_some(net::buffer(buffer), net::use_coro);
    sock.shutdown(sock.shutdown_both);
    co_return;
}

net::task<> client(net::semaphore& sem) {
    co_await sem.async_acquire(net::use_coro);
    net::ip::tcp::socket sock(co_await net::this_context, net::ip::tcp::v4());
    co_await sock.async_connect(
        {net::ip::address::from_string("127.0.0.1"), 20000}, net::use_coro);
    auto uptr_before = std::make_unique<unsigned char[]>(10240);
    unsigned char* ptr_to_buffer = uptr_before.get();
    auto uptr_after = co_await sock.async_read_some(
        net::buffer(ptr_to_buffer, 10240),
        net::detail::proxy<const std::error_code&,
                           std::unique_ptr<unsigned char[]>>(
            [ptr = std::move(uptr_before)](
                auto& token, const std::error_code& e, std::size_t sz) mutable {
                printf("Read result: %s, %zu\n", e.message().c_str(), sz);
                token(e, std::move(ptr));
            },
            net::use_coro));
    assert(uptr_after.get() == ptr_to_buffer);
    co_return;
}

int main() {
    net::io_context ctx;
    net::semaphore sem(ctx);
    co_spawn(ctx, server(sem), net::detached);
    co_spawn(ctx, client(sem), net::detached);
    ctx.run();
    return 0;
}
