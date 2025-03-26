#include <chx/net/thread_executor.hpp>

namespace net = chx::net;

int main() {
    net::thread_executor th;
    th.post([&th, i = 0]() mutable -> int {
        printf("%d\n", i++);
        if (i < 3) {
            return 1;
        } else {
            th.stop();
            return 0;
        }
    });
    th.interrupt();
    th.join();
    return 0;
}
