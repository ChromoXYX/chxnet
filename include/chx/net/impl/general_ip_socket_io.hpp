#pragma once

#include "../error_code.hpp"
#include "../io_context.hpp"
#include "../detail/sfinae_placeholder.hpp"
#include "../buffer.hpp"
#include "../buffer_sequence.hpp"
#include "../async_combine.hpp"

namespace chx::net::detail::tags {
struct read_until {
    template <typename Socket, typename DynamicBuffer, typename StopCond>
    struct operation : StopCond {
        DynamicBuffer dyn_buf;
        Socket& socket;

        template <typename DynBuf, typename SC>
        constexpr operation(Socket& sock, DynBuf&& buf, SC&& sc)
            : socket(sock), dyn_buf(std::forward<DynBuf>(buf)),
              StopCond(std::forward<SC>(sc)) {}

        template <typename Cntl> void operator()(Cntl& cntl) {
            dyn_buf.extend(128);
            socket.async_read_some(buffer(dyn_buf), cntl.next());
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
                    socket.async_read_some(buffer(dyn_buf), cntl.next());
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
}  // namespace chx::net::detail::tags

namespace chx::net::ip::detail::tags {
struct simple_read {};
struct simple_write {};
struct readv {};
struct writev {};
struct connect {};
}  // namespace chx::net::ip::detail::tags

template <>
struct chx::net::detail::async_operation<
    chx::net::ip::detail::tags::simple_read> {
    template <typename Socket, typename CompletionToken>
    decltype(auto) operator()(io_context*, Socket*, const mutable_buffer&,
                              CompletionToken&&);
};

template <>
struct chx::net::detail::async_operation<chx::net::ip::detail::tags::readv> {
    template <typename Socket, typename MutableBufferSequence,
              typename CompletionToken>
    decltype(auto) operator()(io_context*, Socket*, MutableBufferSequence&&,
                              CompletionToken&&);
};

template <>
struct chx::net::detail::async_operation<
    chx::net::ip::detail::tags::simple_write> {
    template <typename Socket, typename CompletionToken>
    decltype(auto) operator()(io_context*, Socket*, const const_buffer&,
                              CompletionToken&&);
};

template <>
struct chx::net::detail::async_operation<chx::net::ip::detail::tags::writev> {
    template <typename Socket, typename ConstBufferSequence,
              typename CompletionToken>
    decltype(auto) operator()(io_context*, Socket*, ConstBufferSequence&&,
                              CompletionToken&&);
};

template <>
struct chx::net::detail::async_operation<chx::net::detail::tags::read_until> {
    template <typename Socket, typename DynamicBuffer, typename StopCond,
              typename CompletionToken>
    decltype(auto) operator()(io_context*, Socket*, DynamicBuffer&&, StopCond&&,
                              CompletionToken&&);
};

template <>
struct chx::net::detail::async_operation<chx::net::ip::detail::tags::connect> {
    template <typename Socket, typename Endpoint, typename CompletionToken>
    decltype(auto) operator()(io_context*, Socket*, const Endpoint&,
                              CompletionToken&& completion_token);
};

template <typename Socket, typename ConstBufferSequence,
          typename CompletionToken>
auto chx::net::detail::async_operation<chx::net::ip::detail::tags::writev>::
operator()(io_context* ctx, Socket* sock,
           ConstBufferSequence&& const_buffer_sequence,
           CompletionToken&& completion_token) -> decltype(auto) {
    io_context::task_t* task = ctx->acquire();
    using __type =
        is_const_buffer_sequence<std::remove_reference_t<ConstBufferSequence>>;
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

template <typename Socket, typename CompletionToken>
auto chx::net::detail::
    async_operation<chx::net::ip::detail::tags::simple_write>::operator()(
        io_context* ctx, Socket* sock, const const_buffer& buf,
        CompletionToken&& completion_token) -> decltype(auto) {
    io_context::task_t* task = ctx->acquire();
    auto* sqe = ctx->get_sqe(task);
    io_uring_prep_write(sqe, sock->native_handler(), buf.data(), buf.size(), 0);

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

template <typename Socket, typename CompletionToken>
auto chx::net::detail::
    async_operation<chx::net::ip::detail::tags::simple_read>::operator()(
        io_context* ctx, Socket* sock, const mutable_buffer& buffer,
        CompletionToken&& completion_token) -> decltype(auto) {
    io_context::task_t* task = ctx->acquire();
    auto* sqe = ctx->get_sqe(task);
    io_uring_prep_read(sqe, sock->native_handler(), buffer.data(),
                       buffer.size(), 0);

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

template <typename Socket, typename MutableBufferSequence,
          typename CompletionToken>
auto chx::net::detail::async_operation<chx::net::ip::detail::tags::readv>::
operator()(io_context* ctx, Socket* sock,
           MutableBufferSequence&& mutable_buffer_sequence,
           CompletionToken&& completion_token) -> decltype(auto) {
    io_context::task_t* task = ctx->acquire();
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
        std::vector<struct iovec> iovec_vec(std::distance(
            mutable_buffer_sequence.begin(), mutable_buffer_sequence.end()));
        auto iterator = iovec_vec.begin();
        for (auto& i : mutable_buffer_sequence) {
            *(iterator++) = detail::to_iovec_mutable(mutable_buffer(i));
        }
        sqe = ctx->get_sqe(task);
        io_uring_prep_readv(sqe, sock->native_handler(), iovec_vec.data(),
                            iovec_vec.size(), 0);
        ctx->submit();
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

template <typename Socket, typename DynamicBuffer, typename StopCond,
          typename CompletionToken>
decltype(auto)
chx::net::detail::async_operation<chx::net::detail::tags::read_until>::
operator()(io_context* ctx, Socket* sock, DynamicBuffer&& dynamic_buffer,
           StopCond&& stop_cond, CompletionToken&& completion_token) {
    return async_combine<const std::error_code&, std::size_t>(
        *ctx,
        tags::read_until::operation(*sock,
                                    std::forward<DynamicBuffer>(dynamic_buffer),
                                    tags::read_until::make_stop_cond(
                                        std::forward<StopCond>(stop_cond))),
        std::forward<CompletionToken>(completion_token));
}

template <typename Socket, typename Endpoint, typename CompletionToken>
decltype(auto)
chx::net::detail::async_operation<chx::net::ip::detail::tags::connect>::
operator()(io_context* ctx, Socket* sock, const Endpoint& ep,
           CompletionToken&& completion_token) {
    io_context::task_t* task = ctx->acquire();
    auto* sqe = ctx->get_sqe(task);
    if (ep.address().is_v4()) {
        auto addr = ep.sockaddr_in();
        io_uring_prep_connect(sqe, sock->native_handler(),
                              (struct sockaddr*)&addr, sizeof(addr));
        ctx->submit();
    } else {
        auto addr = ep.sockaddr_in6();
        io_uring_prep_connect(sqe, sock->native_handler(),
                              (struct sockaddr*)&addr, sizeof(addr));
        ctx->submit();
    }

    return detail::async_token_init(
        task->__M_token.emplace(detail::async_token_generate(
            task,
            [](auto& completion_token,
               io_context::task_t* self) mutable -> int {
                completion_token(self->__M_ec);
                return 0;
            },
            std::forward<CompletionToken>(completion_token))),
        std::forward<CompletionToken>(completion_token));
}
