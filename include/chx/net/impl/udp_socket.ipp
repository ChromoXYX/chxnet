#pragma once

#include "../udp.hpp"
#include "../basic_socket.hpp"

#include "./general_ip_socket_io.hpp"
#include "../detail/version_compare.hpp"

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
class udp::socket : public basic_socket<udp> {
  public:
    socket(io_context& ctx) noexcept(true) : basic_socket<udp>(&ctx) {}
    socket(socket&& other) : basic_socket<udp>(std::move(other)) {}

    socket(io_context& ctx, const udp& protocol) : basic_socket<udp>(&ctx) {
        open(protocol);
    }
    socket(io_context& ctx, const endpoint& ep) : basic_socket<udp>(&ctx) {
        open(ep.protocol());
        bind(ep);
    }
    socket(io_context& ctx, int fd) : basic_socket<udp>(&ctx) { __M_fd = fd; }

    template <typename CompletionToken>
    decltype(auto) async_connect(const endpoint& end_point,
                                 CompletionToken&& completion_token) {
        return net::detail::async_operation<ip::detail::tags::connect>()(
            &get_associated_io_context(), this, end_point,
            std::forward<CompletionToken>(completion_token));
    }

    template <typename ConstBufferSequence, typename CompletionToken>
    decltype(auto)
    async_write(ConstBufferSequence&& const_buffer_sequence,
                CompletionToken&& completion_token,
                net::detail::sfinae_placeholder<
                    std::enable_if_t<is_const_buffer_sequence<
                        std::remove_reference_t<ConstBufferSequence>>::value>>
                    _ = net::detail::sfinae) {
        return net::detail::async_operation<detail::tags::writev>()(
            &get_associated_io_context(), this,
            std::forward<ConstBufferSequence>(const_buffer_sequence),
            net::detail::async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)));
    }

    template <typename ConstBuffer, typename CompletionToken>
    decltype(auto) async_write(
        ConstBuffer&& buffer, CompletionToken&& completion_token,
        net::detail::sfinae_placeholder<
            std::enable_if_t<net::detail::is_const_buffer<ConstBuffer>::value>>
            _ = net::detail::sfinae) {
        return net::detail::async_operation<detail::tags::simple_write>()(
            &get_associated_io_context(), this,
            std::forward<ConstBuffer>(buffer),
            net::detail::async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)));
    }

    template <typename MutableBuffer, typename CompletionToken>
    decltype(auto)
    async_read(MutableBuffer&& buffer, CompletionToken&& completion_token,
               net::detail::sfinae_placeholder<std::enable_if_t<
                   net::detail::is_mutable_buffer<MutableBuffer>::value>>
                   _ = net::detail::sfinae) {
        return net::detail::async_operation<detail::tags::simple_read>()(
            &get_associated_io_context(), this,
            std::forward<MutableBuffer>(buffer),
            net::detail::async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)));
    }

    template <typename MutableBufferSequence, typename CompletionToken>
    decltype(auto)
    async_read(MutableBufferSequence&& mutable_buffer_sequence,
               CompletionToken&& completion_token,
               net::detail::sfinae_placeholder<
                   std::enable_if_t<is_mutable_buffer_sequence<
                       std::remove_reference_t<MutableBufferSequence>>::value>>
                   _ = net::detail::sfinae) {
        return net::detail::async_operation<detail::tags::readv>()(
            &get_associated_io_context(), this,
            std::forward<MutableBufferSequence>(mutable_buffer_sequence),
            net::detail::async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)));
    }

    template <typename DynamicBuffer, typename StopCondition,
              typename CompletionToken>
    decltype(auto) async_read_until(DynamicBuffer&& dynamic_buffer,
                                    StopCondition&& stop_condition,
                                    CompletionToken&& completion_token) {
        return net::detail::async_operation<detail::tags::read_until>()(
            &get_associated_io_context(), this,
            std::forward<DynamicBuffer>(dynamic_buffer),
            std::forward<StopCondition>(stop_condition),
            std::forward<CompletionToken>(completion_token));
    }

    template <typename ConstBuffer, typename CompletionToken>
    decltype(auto) async_sendto(
        ConstBuffer&& buffer, const endpoint& ep,
        CompletionToken&& completion_token,
        net::detail::sfinae_placeholder<
            std::enable_if_t<net::detail::is_const_buffer<ConstBuffer>::value>,
            std::enable_if_t<CHXNET_KERNEL_VERSION_GREATER(6, 0) ||
                             CHXNET_KERNEL_VERSION_EQUAL(6, 0)>>
            _ = net::detail::sfinae) {
        return net::detail::async_operation<detail::tags::udp_sendto>()(
            &get_associated_io_context(), this,
            std::forward<ConstBuffer>(buffer), ep,
            std::forward<CompletionToken>(completion_token));
    }
};
}  // namespace chx::net::ip

template <typename CompletionToken>
decltype(auto)
chx::net::detail::async_operation<chx::net::ip::detail::tags::udp_sendto>::
operator()(io_context* ctx, ip::udp::socket* sock, const const_buffer& buffer,
           const ip::udp::endpoint& ep, CompletionToken&& completion_token) {
    io_context::task_t* task =
        !ctx->is_closed() ? ctx->acquire() : ctx->acquire_after_close();
    if (!ctx->is_closed()) {
        auto* sqe = ctx->get_sqe(task);
        if (ep.address().is_v4()) {
            auto addr = ep.sockaddr_in();
            io_uring_prep_send_zc(sqe, sock->native_handler(), buffer.data(),
                                  buffer.size(), 0, 0);
            io_uring_prep_send_set_addr(sqe, (struct sockaddr*)&addr,
                                        sizeof(addr));
            ctx->submit();
        } else {
            auto addr = ep.sockaddr_in6();
            io_uring_prep_send_zc(sqe, sock->native_handler(), buffer.data(),
                                  buffer.size(), 0, 0);
            io_uring_prep_send_set_addr(sqe, (struct sockaddr*)&addr,
                                        sizeof(addr));
            ctx->submit();
        }
    }

    return detail::async_token_init(
        task->__M_token.emplace(detail::async_token_generate(
            task,
            [](auto& completion_token,
               io_context::task_t* self) mutable -> int {
                completion_token(self->__M_ec,
                                 static_cast<std::size_t>(self->__M_res));
                return 0;
            },
            std::forward<CompletionToken>(completion_token))),
        std::forward<CompletionToken>(completion_token));
}
