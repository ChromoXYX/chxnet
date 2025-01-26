#pragma once

#include "../udp.hpp"
#include "../stream_base.hpp"

#include "./general_io.hpp"
#include "./general_ip_io.hpp"

namespace chx::net::ip::detail::tags {
struct udp_sendto {};
}  // namespace chx::net::ip::detail::tags

template <>
struct chx::net::detail::async_operation<
    chx::net::ip::detail::tags::udp_sendto> {
    template <typename CompletionToken>
    decltype(auto) operator()(io_context*, ip::udp::socket*,
                              const const_buffer&, const ip::udp::endpoint&,
                              CompletionToken&&);
};

namespace chx::net::ip {
class udp::socket : public stream_base {
  public:
    socket(io_context& ctx) noexcept(true) : stream_base(ctx) {}
    socket(socket&& other) : stream_base(std::move(other)) {}

    socket(io_context& ctx, const udp& protocol) : stream_base(ctx) {
        open(protocol);
    }
    socket(io_context& ctx, const endpoint& ep) : stream_base(ctx) {
        open(ep.protocol());
        bind(ep);
    }
    socket(io_context& ctx, int fd) : stream_base(ctx) { __M_fd = fd; }

    constexpr socket& lower_layer() noexcept(true) { return *this; }
    constexpr const socket& lower_layer() const noexcept(true) { return *this; }
    constexpr socket& lowest_layer() noexcept(true) { return lower_layer(); }
    constexpr const socket& lowest_layer() const noexcept(true) {
        return lower_layer();
    }

    void open(const udp& protocol = udp::v4()) {
        if (is_open()) {
            close();
        }
        if (int new_fd = ::socket(protocol.family(), protocol.socket_type(), 0);
            new_fd > 0) {
            __M_fd = new_fd;
        } else {
            __CHXNET_THROW(errno);
        }
    }

    void open(const udp& protocol, std::error_code& ec) noexcept(true) {
        if (is_open()) {
            close(ec);
            if (ec) {
                return;
            }
        }
        if (int new_fd = ::socket(protocol.family(), protocol.socket_type(), 0);
            new_fd > 0) {
            __M_fd = new_fd;
            ec.clear();
        } else {
            net::assign_ec(ec, errno);
        }
    }

    void bind(const typename udp::endpoint& ep) {
        if (ep.address().is_v4()) {
            struct sockaddr_in sar = ep.sockaddr_in();
            if (::bind(__M_fd, reinterpret_cast<sockaddr*>(&sar),
                       sizeof(sar)) == -1) {
                __CHXNET_THROW(errno);
            }
        } else {
            struct sockaddr_in6 sar = ep.sockaddr_in6();
            if (::bind(__M_fd, reinterpret_cast<sockaddr*>(&sar),
                       sizeof(sar)) == -1) {
                __CHXNET_THROW(errno);
            }
        }
    }

    void bind(const typename udp::endpoint& ep,
              std::error_code& ec) noexcept(true) {
        if (ep.address().is_v4()) {
            struct sockaddr_in sar = ep.sockaddr_in();
            if (::bind(__M_fd, reinterpret_cast<sockaddr*>(&sar),
                       sizeof(sar)) == -1) {
                net::assign_ec(ec, errno);
                return;
            }
        } else {
            struct sockaddr_in6 sar = ep.sockaddr_in6();
            if (::bind(__M_fd, reinterpret_cast<sockaddr*>(&sar),
                       sizeof(sar)) == -1) {
                net::assign_ec(ec, errno);
                return;
            }
        }
    }

    typename udp::endpoint local_endpoint(std::error_code& e) const
        noexcept(true) {
        alignas(struct sockaddr_in6) unsigned char buffer[64] = {};
        socklen_t len = sizeof(buffer);
        if (getsockname(native_handler(),
                        reinterpret_cast<struct sockaddr*>(buffer),
                        &len) == 0) {
            return udp::endpoint::make_endpoint(
                reinterpret_cast<struct sockaddr*>(buffer));
        } else {
            assign_ec(e, errno);
            return {};
        }
    }
    typename udp::endpoint local_endpoint() const {
        std::error_code e;
        typename udp::endpoint ep = local_endpoint(e);
        if (!e) {
            return std::move(ep);
        } else {
            __CHXNET_THROW_EC(e);
        }
    }

    template <typename CompletionToken>
    decltype(auto) async_connect(const endpoint& end_point,
                                 CompletionToken&& completion_token) {
        return net::detail::async_operation<detail::tags::connect2>()(
            &get_associated_io_context(),
            net::detail::async_operation<detail::tags::connect2>::c2(
                end_point,
                net::detail::async_token_bind<const std::error_code&>(
                    std::forward<CompletionToken>(completion_token)),
                native_handler()));
    }

    void connect(const ip::udp::endpoint& endpoint,
                 std::error_code& ec) noexcept(true) {
        ec.clear();
        union {
            struct sockaddr_in in;
            struct sockaddr_in6 in6;
        } st = {};
        if (endpoint.address().is_v4()) {
            st.in = endpoint.sockaddr_in();
        } else {
            st.in6 = endpoint.sockaddr_in6();
        }
        if (::connect(native_handler(), (const struct sockaddr*)&st,
                      endpoint.address().is_v4()
                          ? sizeof(sockaddr_in)
                          : sizeof(sockaddr_in6)) == -1) {
            net::assign_ec(ec, errno);
        }
    }
    void connect(const ip::udp::endpoint& endpoint) {
        std::error_code ec;
        connect(endpoint, ec);
        if (ec) {
            __CHXNET_THROW_EC(ec);
        }
    }

    template <typename ConstBufferSequence, typename CompletionToken>
    decltype(auto) async_write_some(
        ConstBufferSequence&& const_buffer_sequence,
        CompletionToken&& completion_token,
        net::detail::sfinae_placeholder<
            std::enable_if_t<is_const_buffer_sequence<
                std::remove_reference_t<ConstBufferSequence>>::value>>
            _ = net::detail::sfinae) {
        return net::detail::async_operation<net::detail::tags::writev>()(
            &get_associated_io_context(), this,
            std::forward<ConstBufferSequence>(const_buffer_sequence),
            net::detail::async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)));
    }

    template <typename ConstBuffer, typename CompletionToken>
    decltype(auto) async_write_some(
        ConstBuffer&& buffer, CompletionToken&& completion_token,
        net::detail::sfinae_placeholder<
            std::enable_if_t<net::detail::is_const_buffer<ConstBuffer>::value>>
            _ = net::detail::sfinae) {
        return net::detail::async_operation<net::detail::tags::simple_write>()(
            &get_associated_io_context(), this,
            std::forward<ConstBuffer>(buffer),
            net::detail::async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)));
    }

    template <typename ConstBuffer>
    std::size_t write(
        ConstBuffer&& const_buffer, std::error_code& ec,
        net::detail::sfinae_placeholder<
            std::enable_if_t<net::detail::is_const_buffer<ConstBuffer>::value>>
            _ = net::detail::sfinae) noexcept(true) {
        ec.clear();
        net::const_buffer buf =
            net::buffer(std::forward<ConstBuffer>(const_buffer));
        ssize_t r = 0;
        if (r = ::write(native_handler(), buf.data(), buf.size()); r == -1) {
            net::assign_ec(ec, errno);
        }
        return r;
    }
    template <typename ConstBuffer>
    std::size_t write(
        ConstBuffer&& const_buffer,
        net::detail::sfinae_placeholder<
            std::enable_if_t<net::detail::is_const_buffer<ConstBuffer>::value>>
            _ = net::detail::sfinae) {
        std::error_code ec;
        std::size_t r = write(std::forward<ConstBuffer>(const_buffer), ec);
        if (!ec) {
            return r;
        } else {
            __CHXNET_THROW_EC(ec);
        }
    }

    template <typename MutableBuffer, typename CompletionToken>
    decltype(auto)
    async_read_some(MutableBuffer&& buffer, CompletionToken&& completion_token,
                    net::detail::sfinae_placeholder<std::enable_if_t<
                        net::detail::is_mutable_buffer<MutableBuffer>::value>>
                        _ = net::detail::sfinae) {
        return net::detail::async_operation<net::detail::tags::simple_read>()(
            &get_associated_io_context(), this,
            std::forward<MutableBuffer>(buffer),
            net::detail::async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)));
    }

    template <typename MutableBuffer>
    std::size_t read(MutableBuffer&& mutable_buffer, std::error_code& ec,
                     net::detail::sfinae_placeholder<std::enable_if_t<
                         net::detail::is_mutable_buffer<MutableBuffer>::value>>
                         _ = net::detail::sfinae) noexcept(true) {
        ec.clear();
        net::mutable_buffer buf =
            net::buffer(std::forward<MutableBuffer>(mutable_buffer));
        ssize_t r = 0;
        if (r = ::read(native_handler(), buf.data(), buf.size()); r == -1) {
            net::assign_ec(ec, errno);
        }
        return r;
    }
    template <typename MutableBuffer>
    std::size_t read(MutableBuffer&& mutable_buffer,
                     net::detail::sfinae_placeholder<std::enable_if_t<
                         net::detail::is_mutable_buffer<MutableBuffer>::value>>
                         _ = net::detail::sfinae) {
        std::error_code ec;
        std::size_t r = read(std::forward<MutableBuffer>(mutable_buffer), ec);
        if (!ec) {
            return r;
        } else {
            __CHXNET_THROW_EC(ec);
        }
    }

    template <typename MutableBufferSequence, typename CompletionToken>
    decltype(auto) async_read_some(
        MutableBufferSequence&& mutable_buffer_sequence,
        CompletionToken&& completion_token,
        net::detail::sfinae_placeholder<
            std::enable_if_t<is_mutable_buffer_sequence<
                std::remove_reference_t<MutableBufferSequence>>::value>>
            _ = net::detail::sfinae) {
        return net::detail::async_operation<net::detail::tags::readv>()(
            &get_associated_io_context(), this,
            std::forward<MutableBufferSequence>(mutable_buffer_sequence),
            net::detail::async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)));
    }

    template <typename ConstBuffer, typename CompletionToken>
    decltype(auto) async_sendto(
        ConstBuffer&& buffer, const endpoint& ep,
        CompletionToken&& completion_token,
        net::detail::sfinae_placeholder<
            std::enable_if_t<net::detail::is_const_buffer<ConstBuffer>::value>>
            _ = net::detail::sfinae) {
        return net::detail::async_operation<detail::tags::udp_sendto>()(
            &get_associated_io_context(), this,
            std::forward<ConstBuffer>(buffer), ep,
            std::forward<CompletionToken>(completion_token));
    }

    template <typename ConstBuffer>
    std::size_t sendto(
        ConstBuffer&& const_buffer, const endpoint& ep, std::error_code& ec,
        net::detail::sfinae_placeholder<
            std::enable_if_t<net::detail::is_const_buffer<ConstBuffer>::value>>
            _ = net::detail::sfinae) noexcept(true) {
        ec.clear();
        union {
            struct sockaddr_in in;
            struct sockaddr_in6 in6;
        } st = {};
        if (ep.address().is_v4()) {
            st.in = ep.sockaddr_in();
        } else {
            st.in6 = ep.sockaddr_in6();
        }
        net::const_buffer buffer =
            net::buffer(std::forward<ConstBuffer>(const_buffer));
        ssize_t r = 0;
        if (r = ::sendto(native_handler(), buffer.data(), buffer.size(), 0,
                         (const struct sockaddr*)&st,
                         ep.address().is_v4() ? sizeof(sockaddr_in)
                                              : sizeof(sockaddr_in6));
            r == -1) {
            net::assign_ec(ec, errno);
        }
        return r;
    }
    template <typename ConstBuffer>
    std::size_t sendto(
        ConstBuffer&& const_buffer, const endpoint& ep,
        net::detail::sfinae_placeholder<
            std::enable_if_t<net::detail::is_const_buffer<ConstBuffer>::value>>
            _ = net::detail::sfinae) {
        std::error_code ec;
        std::size_t r = sendto(std::forward<ConstBuffer>(const_buffer), ep, ec);
        if (!ec) {
            return r;
        } else {
            __CHXNET_THROW_EC(ec);
        }
    }
};
}  // namespace chx::net::ip

template <typename CompletionToken>
decltype(auto)
chx::net::detail::async_operation<chx::net::ip::detail::tags::udp_sendto>::
operator()(io_context* ctx, ip::udp::socket* sock, const const_buffer& buffer,
           const ip::udp::endpoint& ep, CompletionToken&& completion_token) {
    io_context::task_t* task = ctx->acquire();
    auto* sqe = ctx->get_sqe(task);

    struct msghdr msg = {};
    struct iovec io = {};
    io.iov_base = const_cast<void*>(buffer.data());
    io.iov_len = buffer.size();
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    if (ep.address().is_v4()) {
        auto addr = ep.sockaddr_in();
        msg.msg_name = &addr;
        msg.msg_namelen = sizeof(addr);
        io_uring_prep_sendmsg(sqe, sock->native_handler(), &msg, 0);
        ctx->submit();
    } else {
        auto addr = ep.sockaddr_in6();
        msg.msg_name = &addr;
        msg.msg_namelen = sizeof(addr);
        io_uring_prep_sendmsg(sqe, sock->native_handler(), &msg, 0);
        ctx->submit();
    }

    return detail::async_token_init(
        task->__M_token.emplace(detail::async_token_generate(
            task,
            [](auto& completion_token,
               io_context::task_t* self) mutable -> int {
                completion_token(get_ec(self),
                                 static_cast<std::size_t>(get_res(self)));
                return 0;
            },
            std::forward<CompletionToken>(completion_token))),
        std::forward<CompletionToken>(completion_token));
}
