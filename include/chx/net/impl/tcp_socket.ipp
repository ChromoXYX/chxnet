#pragma once

#include <linux/limits.h>
#include <string_view>
#include <type_traits>

#include "../tcp.hpp"
#include "../buffer.hpp"
#include "../buffer_sequence.hpp"
#include "../detail/sfinae_placeholder.hpp"

#include "../async_token.hpp"
#include "../async_combine.hpp"

#ifndef CHXNET_SPLICE_SIZE
#define CHXNET_SPLICE_SIZE 65536
#endif

// TODO: send_file was written when drunk, so...

namespace chx::net::ip::detail::tags {
struct simple_read {};
struct simple_write {};
struct readv {};
struct writev {};

struct read_until {
    template <typename Socket, typename DynamicBuffer, typename StopCond>
    struct operation : StopCond {
        DynamicBuffer dyn_buf;
        Socket& socket;

        template <typename DynBuf, typename SC>
        constexpr operation(Socket& sock, DynBuf&& buf, SC&& sc)
            : socket(sock), dyn_buf(std::forward<DynBuf>(buf)),
              StopCond(std::forward<SC>(sc)) {}

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& ec) {
            dyn_buf.extend(128);
            socket.async_read(buffer(dyn_buf), cntl.next());
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& ec, std::size_t sz) {
            // when encountered eof, sz is 0. so consume(sz) will take no
            // effect. dyn_buf.view() guarantees valid return value: a
            // string_view to a piece of memory or just empty. and shrink() will
            // take no effect if dyn_buf is empty, pos will also be a valid and
            // meaningful value or just npos.
            if (!ec || ec == errc::eof) {
                dyn_buf.consume(sz);
                std::size_t pos = StopCond::operator()(dyn_buf.view());
                if (pos != std::string_view::npos || ec == errc::eof) {
                    dyn_buf.shrink();
                    // pos == npos and ec == eof will not occur at same time, if
                    // nothing went wrong.
                    cntl.complete(ec, pos);
                } else {
                    dyn_buf.extend(128);
                    socket.async_read(buffer(dyn_buf), cntl.next());
                }
            } else {
                cntl.complete(ec, 0);
            }
        }
    };
    template <typename Socket, typename DynamicBuffer, typename StopCond>
    operation(Socket&, DynamicBuffer&&, StopCond&&)
        -> operation<Socket, std::remove_reference_t<DynamicBuffer>,
                     std::remove_reference_t<StopCond>>;

    struct stop_cond {
        std::basic_string_view<unsigned char> pattern;

        template <typename CharT>
        constexpr stop_cond(std::basic_string_view<CharT> view) noexcept(true)
            : pattern(static_cast<const unsigned char*>(
                          static_cast<const void*>(view.data())),
                      view.size()) {}
        template <typename CharT, std::size_t Size>
        constexpr stop_cond(const CharT (&s)[Size]) noexcept(true)
            : pattern(static_cast<const unsigned char*>(
                          static_cast<const void*>(s)),
                      Size - 1) {}

        constexpr std::size_t
        operator()(std::basic_string_view<unsigned char> str) noexcept(true) {
            std::size_t r = str.npos;
            return r = str.find(pattern),
                   r != str.npos ? r + pattern.size() : r;
        }
    };

    struct stop_cond_char {
        unsigned char const c;

        template <typename CharT>
        constexpr stop_cond_char(
            CharT ch,
            net::detail::sfinae_placeholder<
                std::enable_if_t<std::is_convertible_v<CharT, unsigned char>>>
                _ = net::detail::sfinae) noexcept(true)
            : c(ch) {}

        constexpr std::size_t
        operator()(std::basic_string_view<unsigned char> str) noexcept(true) {
            std::size_t r = str.npos;
            return r = str.find(c), r != str.npos ? r + 1 : r;
        }
    };

    template <typename T>
    constexpr static decltype(auto) make_stop_cond(T&& t) noexcept(true) {
        if constexpr (std::is_constructible_v<stop_cond_char, T&&>) {
            return stop_cond_char(std::forward<T>(t));
        } else {
            return stop_cond(std::forward<T>(t));
        }
    }
};

struct splice {};
struct send_file {
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
    chx::net::ip::detail::tags::simple_read> {
    template <typename CompletionToken>
    decltype(auto) operator()(io_context*, ip::tcp::socket*,
                              const mutable_buffer&, CompletionToken&&);
};

template <>
struct chx::net::detail::async_operation<chx::net::ip::detail::tags::readv> {
    template <typename MutableBufferSequence, typename CompletionToken>
    decltype(auto) operator()(io_context*, ip::tcp::socket*,
                              MutableBufferSequence&&, CompletionToken&&);
};

template <>
struct chx::net::detail::async_operation<
    chx::net::ip::detail::tags::simple_write> {
    template <typename CompletionToken>
    decltype(auto) operator()(io_context*, ip::tcp::socket*,
                              const const_buffer&, CompletionToken&&);
};

template <>
struct chx::net::detail::async_operation<chx::net::ip::detail::tags::writev> {
    template <typename ConstBufferSequence, typename CompletionToken>
    decltype(auto) operator()(io_context*, ip::tcp::socket*,
                              ConstBufferSequence&&, CompletionToken&&);
};

template <>
struct chx::net::detail::async_operation<
    chx::net::ip::detail::tags::read_until> {
    template <typename DynamicBuffer, typename StopCond,
              typename CompletionToken>
    decltype(auto) operator()(io_context*, ip::tcp::socket*, DynamicBuffer&&,
                              StopCond&&, CompletionToken&&);
};

template <>
struct chx::net::detail::async_operation<
    chx::net::ip::detail::tags::send_file> {
    template <typename File, typename CompletionToken>
    decltype(auto) operator()(io_context*, ip::tcp::socket*, File&&,
                              CompletionToken&&);
};

template <>
struct chx::net::detail::async_operation<chx::net::ip::detail::tags::splice> {
    template <typename CompletionToken>
    decltype(auto) operator()(io_context*, ip::tcp::socket*, int, int,
                              std::size_t, CompletionToken&&);
};

namespace chx::net::ip {
class tcp::socket : public socket_base {
    template <typename Sock, typename File>
    friend struct detail::tags::send_file::operation;

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
    socket(socket&& other) : socket_base(std::move(other)) {}

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

    template <typename File, typename CompletionToken>
    decltype(auto) async_send_file(File&& file,
                                   CompletionToken&& completion_token) {
        return net::detail::async_operation<detail::tags::send_file>()(
            &get_associated_io_context(), this, std::forward<File>(file),
            std::forward<CompletionToken>(completion_token));
    }

  protected:
    template <typename CompletionToken>
    decltype(auto) async_splice(int fd_in, int fd_out, std::size_t len,
                                CompletionToken&& completion_token) {
        return net::detail::async_operation<detail::tags::splice>()(
            &get_associated_io_context(), this, fd_in, fd_out, len,
            std::forward<CompletionToken>(completion_token));
    }
};
}  // namespace chx::net::ip

template <typename ConstBufferSequence, typename CompletionToken>
auto chx::net::detail::async_operation<chx::net::ip::detail::tags::writev>::
operator()(io_context* ctx, ip::tcp::socket* sock,
           ConstBufferSequence&& const_buffer_sequence,
           CompletionToken&& completion_token) -> decltype(auto) {
    io_context::task_t* task =
        !ctx->is_closed() ? ctx->acquire() : ctx->acquire_after_close();
    if (!ctx->is_closed()) {
        using __type = is_const_buffer_sequence<
            std::remove_reference_t<ConstBufferSequence>>;
        io_uring_sqe* sqe = nullptr;
        if constexpr (__type::has_static_size) {
            const auto iovec_arr = generate_iovec_array_const(
                const_buffer_sequence,
                std::make_integer_sequence<std::size_t, __type::static_size>());
            sqe = ctx->get_sqe(task);
            io_uring_prep_writev(sqe, sock->native_handler(), iovec_arr.data(),
                                 iovec_arr.size(), 0);
            ctx->submit();

        } else {
            std::vector<struct iovec> iovec_vec(std::distance(
                const_buffer_sequence.begin(), const_buffer_sequence.end()));
            auto iterator = iovec_vec.begin();
            for (const auto& i : const_buffer_sequence) {
                *(iterator++) = detail::to_iovec_const(const_buffer(i));
            }
            sqe = ctx->get_sqe(task);
            io_uring_prep_writev(sqe, sock->native_handler(), iovec_vec.data(),
                                 iovec_vec.size(), 0);
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

template <typename CompletionToken>
auto chx::net::detail::
    async_operation<chx::net::ip::detail::tags::simple_write>::operator()(
        io_context* ctx, ip::tcp::socket* sock, const const_buffer& buf,
        CompletionToken&& completion_token) -> decltype(auto) {
    io_context::task_t* task =
        !ctx->is_closed() ? ctx->acquire() : ctx->acquire_after_close();
    if (!ctx->is_closed()) {
        auto* sqe = ctx->get_sqe(task);
        io_uring_prep_write(sqe, sock->native_handler(), buf.data(), buf.size(),
                            0);
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

template <typename CompletionToken>
auto chx::net::detail::
    async_operation<chx::net::ip::detail::tags::simple_read>::operator()(
        io_context* ctx, ip::tcp::socket* sock, const mutable_buffer& buffer,
        CompletionToken&& completion_token) -> decltype(auto) {
    io_context::task_t* task =
        !ctx->is_closed() ? ctx->acquire() : ctx->acquire_after_close();
    if (!ctx->is_closed()) {
        auto* sqe = ctx->get_sqe(task);
        io_uring_prep_read(sqe, sock->native_handler(), buffer.data(),
                           buffer.size(), 0);
    }
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

template <typename MutableBufferSequence, typename CompletionToken>
auto chx::net::detail::async_operation<chx::net::ip::detail::tags::readv>::
operator()(io_context* ctx, ip::tcp::socket* sock,
           MutableBufferSequence&& mutable_buffer_sequence,
           CompletionToken&& completion_token) -> decltype(auto) {
    io_context::task_t* task =
        !ctx->is_closed() ? ctx->acquire() : ctx->acquire_after_close();
    if (!ctx->is_closed()) {
        using __type = is_mutable_buffer_sequence<
            std::remove_reference_t<MutableBufferSequence>>;
        io_uring_sqe* sqe = nullptr;
        if constexpr (__type::has_static_size) {
            auto iovec_arr = generate_iovec_array_mutable(
                mutable_buffer_sequence,
                std::make_integer_sequence<std::size_t, __type::static_size>());
            sqe = ctx->get_sqe(task);
            io_uring_prep_readv(sqe, sock->native_handler(), iovec_arr.data(),
                                iovec_arr.size(), 0);
            ctx->submit();
        } else {
            std::vector<struct iovec> iovec_vec(
                std::distance(mutable_buffer_sequence.begin(),
                              mutable_buffer_sequence.end()));
            auto iterator = iovec_vec.begin();
            for (auto& i : mutable_buffer_sequence) {
                *(iterator++) = detail::to_iovec_mutable(mutable_buffer(i));
            }
            sqe = ctx->get_sqe(task);
            io_uring_prep_readv(sqe, sock->native_handler(), iovec_vec.data(),
                                iovec_vec.size(), 0);
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

template <typename DynamicBuffer, typename StopCond, typename CompletionToken>
decltype(auto)
chx::net::detail::async_operation<chx::net::ip::detail::tags::read_until>::
operator()(io_context* ctx, ip::tcp::socket* sock,
           DynamicBuffer&& dynamic_buffer, StopCond&& stop_cond,
           CompletionToken&& completion_token) {
    return async_combine<const std::error_code&, std::size_t>(
        *ctx,
        ip::detail::tags::read_until::operation(
            *sock, std::forward<DynamicBuffer>(dynamic_buffer),
            ip::detail::tags::read_until::make_stop_cond(
                std::forward<StopCond>(stop_cond))),
        std::forward<CompletionToken>(completion_token));
}

template <typename File, typename CompletionToken>
decltype(auto)
chx::net::detail::async_operation<chx::net::ip::detail::tags::send_file>::
operator()(io_context* ctx, ip::tcp::socket* sock, File&& file,
           CompletionToken&& completion_token) {
    return async_combine<const std::error_code&, std::size_t>(
        *ctx,
        ip::detail::tags::send_file::operation(*sock, std::forward<File>(file)),
        std::forward<CompletionToken>(completion_token));
}

template <typename CompletionToken>
decltype(auto)
chx::net::detail::async_operation<chx::net::ip::detail::tags::splice>::
operator()(io_context* ctx, ip::tcp::socket* sock, int fd_in, int fd_out,
           std::size_t len, CompletionToken&& completion_token) {
    io_context::task_t* task =
        !ctx->is_closed() ? ctx->acquire() : ctx->acquire_after_close();
    if (!ctx->is_closed()) {
        auto* sqe = ctx->get_sqe(task);
        io_uring_prep_splice(sqe, fd_in, -1, fd_out, -1, len, 0);
    }
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
