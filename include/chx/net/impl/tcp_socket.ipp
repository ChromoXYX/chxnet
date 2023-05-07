#pragma once

#include <linux/limits.h>
#include <string_view>
#include <type_traits>

#include "../tcp.hpp"

#include "./general_ip_socket_io.hpp"

#ifndef CHXNET_SPLICE_SIZE
#define CHXNET_SPLICE_SIZE 65536
#endif

// TODO: send_file was written when drunk, so...

namespace chx::net::ip::detail::tags {
struct tcp_splice {};
struct tcp_send_file {
    // we need to calculate how many bytes are sent, so link is useless here.
    template <typename Socket, typename File> struct operation {
        Socket& sock;
        File file;

        int pipes[2] = {};
        enum Status : char { file_to_pipe, pipe_to_sock } status = file_to_pipe;
        std::size_t total_bytes = 0;

        template <typename S, typename F>
        operation(S&& s, F&& f)
            : sock(std::forward<S>(s)), file(std::forward<F>(f)) {}

        ~operation() {
            if (pipes[0]) {
                close_pipe();
            }
        }

        void close_pipe() noexcept(true) {
            ::close(pipes[0]);
            ::close(pipes[1]);
            ::memset(pipes, 0, sizeof(pipes));
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& ec) {
            if (::pipe(pipes) != -1) {
                sock.async_splice(file.native_handler(), pipes[1],
                                  CHXNET_SPLICE_SIZE, cntl.next());
                status = pipe_to_sock;
            } else {
                cntl.async_nop(
                    [err = errno](auto& cntl,
                                  const std::error_code& ec) mutable {
                        cntl.complete(!ec ? net::detail::make_ec(err) : ec, 0);
                    });
            }
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& ec, std::size_t sz) {
            if (!ec || ec == errc::eof) {
                if (sz == 0) {
                    close_pipe();
                    cntl.complete(std::error_code{}, total_bytes);
                    return;
                }
                switch (status) {
                case pipe_to_sock: {
                    // dump every bytes in pipe to socket
                    sock.async_splice(pipes[0], sock.native_handler(),
                                      CHXNET_SPLICE_SIZE, cntl.next());
                    status = file_to_pipe;
                    return;
                }
                case file_to_pipe: {
                    // sz refers to the number of bytes transfered from pipe to
                    // socket.
                    total_bytes += sz;
                    sock.async_splice(file.native_handler(), pipes[1],
                                      CHXNET_SPLICE_SIZE, cntl.next());
                    status = pipe_to_sock;
                    return;
                }
                }
            } else {
                close_pipe();
                cntl.complete(ec, total_bytes);
            }
        }
    };
    template <typename Socket, typename File>
    operation(Socket&&, File&&) -> operation<std::remove_reference_t<Socket>,
                                             std::remove_reference_t<File>>;
};
}  // namespace chx::net::ip::detail::tags

template <>
struct chx::net::detail::async_operation<
    chx::net::ip::detail::tags::tcp_send_file> {
    template <typename File, typename CompletionToken>
    decltype(auto) operator()(io_context*, ip::tcp::socket*, File&&,
                              CompletionToken&&);
};

template <>
struct chx::net::detail::async_operation<
    chx::net::ip::detail::tags::tcp_splice> {
    template <typename CompletionToken>
    decltype(auto) operator()(io_context*, ip::tcp::socket*, int, int,
                              std::size_t, CompletionToken&&);
};

namespace chx::net::ip {
class tcp::socket : public socket_base {
    template <typename Sock, typename File>
    friend struct detail::tags::tcp_send_file::operation;

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

    //     template <typename File, typename CompletionToken>
    //     decltype(auto) async_send_file(File&& file,
    //                                    CompletionToken&& completion_token) {
    //         return
    //         net::detail::async_operation<detail::tags::tcp_send_file>()(
    //             &get_associated_io_context(), this, std::forward<File>(file),
    //             std::forward<CompletionToken>(completion_token));
    //     }

    //   protected:
    //     template <typename CompletionToken>
    //     decltype(auto) async_splice(int fd_in, int fd_out, std::size_t len,
    //                                 CompletionToken&& completion_token) {
    //         return net::detail::async_operation<detail::tags::tcp_splice>()(
    //             &get_associated_io_context(), this, fd_in, fd_out, len,
    //             std::forward<CompletionToken>(completion_token));
    //     }
};
}  // namespace chx::net::ip

template <typename File, typename CompletionToken>
decltype(auto)
chx::net::detail::async_operation<chx::net::ip::detail::tags::tcp_send_file>::
operator()(io_context* ctx, ip::tcp::socket* sock, File&& file,
           CompletionToken&& completion_token) {
    return async_combine<const std::error_code&, std::size_t>(
        *ctx,
        ip::detail::tags::tcp_send_file::operation(*sock,
                                                   std::forward<File>(file)),
        std::forward<CompletionToken>(completion_token));
}

template <typename CompletionToken>
decltype(auto)
chx::net::detail::async_operation<chx::net::ip::detail::tags::tcp_splice>::
operator()(io_context* ctx, ip::tcp::socket* sock, int fd_in, int fd_out,
           std::size_t len, CompletionToken&& completion_token) {
    io_context::task_t* task = ctx->acquire();
    auto* sqe = ctx->get_sqe(task);
    io_uring_prep_splice(sqe, fd_in, -1, fd_out, -1, len, 0);

    return detail::async_token_init(
        task->__M_token.emplace(detail::async_token_generate(
            task,
            [](auto& completion_token,
               io_context::task_t* self) mutable -> int {
                if (self->__M_res == 0) {
                    detail::assign_ec(self->__M_ec, errc::eof);
                }
                completion_token(self->__M_ec,
                                 static_cast<std::size_t>(self->__M_res));
                return 0;
            },
            std::forward<CompletionToken>(completion_token))),
        std::forward<CompletionToken>(completion_token));
}
