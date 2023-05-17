#pragma once

#include <linux/limits.h>
#include <string_view>
#include <type_traits>

#include "../tcp.hpp"

#include "./general_ip_socket_io.hpp"

#ifndef CHXNET_SPLICE_SIZE
#define CHXNET_SPLICE_SIZE 65536
#endif

namespace chx::net::ip::detail::tags {}  // namespace chx::net::ip::detail::tags

namespace chx::net::ip {
class tcp::socket : public socket_base {
  public:
    /**
     * @brief Construct a new socket object.
     *
     * @param ctx The associated io_context.
     */
    socket(io_context& ctx) : socket_base(&ctx) {}
    /**
     * @brief Construct a new and opened socket object.
     *
     * @param ctx The associated io_context.
     * @param protocol The protocol selected for the socket.
     */
    socket(io_context& ctx, const tcp& protocol) : socket_base(&ctx) {
        open(protocol);
    }
    /**
     * @brief Construct a new socket object, which bound to specific endpoint.
     *
     * @param ctx The associated io_context.
     * @param ep The endpoint assigned to the socket.
     */
    socket(io_context& ctx, const endpoint& ep) : socket_base(&ctx) {
        open(ep.protocol());
        bind(ep);
    }
    /**
     * @brief Construct a new socket object from a native handler.
     *
     * @param ctx The associated io_context.
     * @param fd The native handler assigned to the socket.
     */
    socket(io_context& ctx, int fd) : socket_base(&ctx) { __M_fd = fd; }
    /**
     * @brief Move-construct a new socket object.
     *
     * @param other The socket to be moved.
     */
    socket(socket&& other) noexcept(true) : socket_base(std::move(other)) {}

    socket& operator=(socket&& other) noexcept(true) {
        if (this == &other) {
            return *this;
        }
        socket_base::operator=(std::move(other));
        return *this;
    }

    template <typename CompletionToken>
    decltype(auto) async_connect(const ip::tcp::endpoint& end_point,
                                 CompletionToken&& completion_token) {
        return net::detail::async_operation<ip::detail::tags::connect>()(
            &get_associated_io_context(), this, end_point,
            std::forward<CompletionToken>(completion_token));
    }

    /**
     * @brief Submit a write async task for a sequence of buffers.
     *
     * @tparam ConstBufferSequence
     * @tparam CompletionToken Callable object with signature
     * \code
     * void(const std::error_code&, std::size_t)
     * \endcode
     * @param const_buffer_sequence
     * @param completion_token Completion token which will be invoked when the
     * async task is completed.
     * @return decltype(auto)
     */
    template <typename ConstBufferSequence, typename CompletionToken>
    decltype(auto) async_write_some(
        ConstBufferSequence&& const_buffer_sequence,
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

    /**
     * @brief Submit a write async task for a single buffer.
     *
     * @tparam ConstBuffer
     * @tparam CompletionToken Callable object with signature
     * \code
     * void(const std::error_code&, std::size_t)
     * \endcode
     * @param buffer
     * @param completion_token Completion token which will be invoked when the
     * async task is completed.
     * @return decltype(auto)
     */
    template <typename ConstBuffer, typename CompletionToken>
    decltype(auto) async_write_some(
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

    /**
     * @brief Submit a read async task for a single buffer.
     *
     * @tparam MutableBuffer
     * @tparam CompletionToken Callable object with signature
     * \code
     * void(const std::error_code&, std::size_t)
     * \endcode
     * @param buffer
     * @param completion_token Completion token which will be invoked when the
     * async task is completed.
     * @return decltype(auto)
     */
    template <typename MutableBuffer, typename CompletionToken>
    decltype(auto)
    async_read_some(MutableBuffer&& buffer, CompletionToken&& completion_token,
                    net::detail::sfinae_placeholder<std::enable_if_t<
                        net::detail::is_mutable_buffer<MutableBuffer>::value>>
                        _ = net::detail::sfinae) {
        return net::detail::async_operation<detail::tags::simple_read>()(
            &get_associated_io_context(), this,
            std::forward<MutableBuffer>(buffer),
            net::detail::async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)));
    }

    /**
     * @brief Submit a read async task for a sequence of buffers.
     *
     * @tparam MutableBufferSequence
     * @tparam CompletionToken Callable object with signature
     * \code
     * void(const std::error_code&, std::size_t)
     * \endcode
     * @param mutable_buffer_sequence
     * @param completion_token Completion token which will be invoked when the
     * async task is completed.
     * @return decltype(auto)
     */
    template <typename MutableBufferSequence, typename CompletionToken>
    decltype(auto) async_read_some(
        MutableBufferSequence&& mutable_buffer_sequence,
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
};
}  // namespace chx::net::ip
