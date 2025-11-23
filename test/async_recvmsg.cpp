#include <chx/net.hpp>
#include <chx/net/coroutine2.hpp>
#include <sys/socket.h>
#include <iostream>
#include <cstring>
#include <netdb.h>
#include <arpa/inet.h>

namespace net = chx::net;

net::task<> udp_receiver(net::semaphore& sem,
                         net::cancellation_signal& timeout_cncl) {
    net::io_context& ctx = co_await net::this_context;

    // 创建UDP socket并绑定到端口
    net::ip::udp::socket sock(ctx, net::ip::udp::v4());
    sock.bind({net::ip::address::from_string("127.0.0.1"), 40001});

    // 通知发送端可以开始发送
    sem.release();

    // 准备接收缓冲区和地址结构
    char buffer[1024] = {};
    struct sockaddr_storage sender_addr = {};
    struct iovec iov = {};
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);

    char cmsg_buffer[1024] = {};
    struct msghdr msg = {};
    msg.msg_name = &sender_addr;
    msg.msg_namelen = sizeof(sender_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buffer;
    msg.msg_controllen = sizeof(cmsg_buffer);

    // 使用async_recvmsg接收消息
    auto [ec, bytes_received] =
        co_await net::async_recvmsg(sock, msg, net::as_tuple(net::use_coro));

    if (ec) {
        std::cerr << "recvmsg error: " << ec.message() << std::endl;
        co_return;
    }

    std::cout << "Received " << bytes_received << " bytes." << std::endl;
    std::cout << "  msg_namelen: " << msg.msg_namelen << std::endl;
    std::cout << "  msg_controllen: " << msg.msg_controllen << std::endl;
    std::cout << "  msg_flags: " << msg.msg_flags << std::endl;

    if (msg.msg_namelen > 0) {
        char host[NI_MAXHOST];
        char service[NI_MAXSERV];
        if (getnameinfo(reinterpret_cast<struct sockaddr*>(&sender_addr),
                        msg.msg_namelen, host, sizeof(host), service,
                        sizeof(service),
                        NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
            std::cout << "  Sender address: " << host << ":" << service
                      << std::endl;
        } else {
            std::cout << "  Sender address: <error in getnameinfo>"
                      << std::endl;
        }
    }

    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        std::cout << "  Control Message:" << std::endl;
        std::cout << "    cmsg_len: " << cmsg->cmsg_len << std::endl;
        std::cout << "    cmsg_level: " << cmsg->cmsg_level << std::endl;
        std::cout << "    cmsg_type: " << cmsg->cmsg_type << std::endl;
    }

    std::string received_data(buffer, bytes_received);
    std::cout << "Received data: " << received_data << std::endl;

    // 验证接收到的数据
    if (received_data == "Hello from UDP!") {
        std::cout << "Test PASSED: Received expected message" << std::endl;
    } else {
        std::cerr << "Test FAILED: Unexpected message: " << received_data
                  << std::endl;
        std::exit(1);
    }

    timeout_cncl.emit();

    co_return;
}

net::task<> udp_sender(net::semaphore& sem,
                       net::cancellation_signal& timeout_cncl) {
    net::io_context& ctx = co_await net::this_context;

    // 等待接收端准备好
    co_await sem.async_acquire(net::use_coro);

    // 创建UDP socket
    net::ip::udp::socket sock(ctx, net::ip::udp::v4());

    // 连接到接收端
    net::ip::udp::endpoint target(net::ip::address::from_string("127.0.0.1"),
                                  40001);

    auto [ec] =
        co_await sock.async_connect(target, net::as_tuple(net::use_coro));

    if (ec) {
        std::cerr << "connect error: " << ec.message() << std::endl;
        std::exit(1);
    }

    // 发送消息
    const char* message = "Hello from UDP!";
    auto [write_ec, bytes_sent] = co_await sock.async_write_some(
        net::buffer(message, std::strlen(message)),
        net::as_tuple(net::use_coro));

    if (write_ec) {
        std::cerr << "write error: " << write_ec.message() << std::endl;
        std::exit(1);
    }

    std::cout << "Sent " << bytes_sent << " bytes" << std::endl;

    timeout_cncl.emit();

    co_return;
}

net::task<> timeout_handler(net::fixed_timer& timer,
                            net::cancellation_signal& timeout_cncl) {
    auto [ec] = co_await timer.async_register(
        std::chrono::seconds(5),
        net::bind_cancellation_signal(timeout_cncl,
                                      net::as_tuple(net::use_coro)));
    if (!ec) {
        std::cerr << "Test TIMEOUT" << std::endl;
        std::exit(1);
    }
    co_return;
}

int main() {
    net::io_context ctx;
    net::semaphore sem(ctx);
    net::fixed_timer timer(ctx);
    net::cancellation_signal timeout_cncl;

    co_spawn(ctx, udp_receiver(sem, timeout_cncl), net::detached);
    co_spawn(ctx, udp_sender(sem, timeout_cncl), net::detached);
    co_spawn(ctx, timeout_handler(timer, timeout_cncl), net::detached);

    ctx.run();
    return 0;
}
