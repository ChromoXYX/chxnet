#pragma once

#include "../error_code.hpp"
#include "../io_context.hpp"
#include "../detail/sfinae_placeholder.hpp"
#include "../buffer.hpp"
#include "../buffer_sequence.hpp"
#include "../async_combine.hpp"
#include "../ip.hpp"
#include "../dynamic_buffer.hpp"

#include <netinet/in.h>

namespace chx::net::detail::tags {
struct read_until {
    template <typename Socket, typename DynamicBuffer, typename StopCond,
              std::size_t Type, typename CntlType = void>
    struct operation : StopCond {
        DynamicBuffer dyn_buf;
        Socket& socket;

        template <typename CntlT>
        using rebind = operation<Socket, DynamicBuffer, StopCond, Type, CntlT>;

        template <typename DynBuf, typename SC>
        constexpr operation(Socket& sock, DynBuf&& buf, SC&& sc)
            : StopCond(std::forward<SC>(sc)), socket(sock),
              dyn_buf(std::forward<DynBuf>(buf)) {}
        template <typename SC>
        constexpr operation(Socket& sock, SC&& sc)
            : StopCond(std::forward<SC>(sc)), socket(sock),
              dyn_buf(dynamic_buffer{StopCond::container()}) {}

        template <typename Cntl> void operator()(Cntl& cntl) {
            static_assert(!std::is_same_v<CntlType, void>);
            dyn_buf.extend(StopCond::extend_size());
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
                    if constexpr (Type == 0) {
                        cntl.complete(ec, pos);
                    } else {
                        cntl.complete(
                            ec, std::make_pair(
                                    std::move(dyn_buf.underlying_container()),
                                    pos));
                    }
                } else {
                    dyn_buf.extend(StopCond::extend_size());
                    if (dyn_buf.size()) {
                        socket.async_read_some(buffer(dyn_buf), cntl.next());
                    } else {
                        // max size
                        if constexpr (Type == 0) {
                            cntl.complete(ec, std::string_view::npos);
                        } else {
                            cntl.complete(
                                ec,
                                std::make_pair(
                                    std::move(dyn_buf.underlying_container()),
                                    std::string_view::npos));
                        }
                    }
                }
            } else {
                if constexpr (Type == 0) {
                    cntl.complete(ec, 0);
                } else {
                    cntl.complete(
                        ec, std::make_pair(
                                std::move(dyn_buf.underlying_container()), 0));
                }
            }
        }
    };
    template <typename Socket, typename DynamicBuffer, typename StopCond>
    operation(Socket&, DynamicBuffer&&, StopCond&&)
        -> operation<Socket, std::remove_reference_t<DynamicBuffer>,
                     std::remove_reference_t<StopCond>, 0>;
    template <typename Socket, typename StopCond>
    operation(Socket&, StopCond&&) -> operation<
        Socket,
        net::dynamic_buffer<typename std::decay_t<StopCond>::container_type>,
        std::remove_reference_t<StopCond>, 1>;

    struct stop_cond {
        std::basic_string_view<unsigned char> pattern;

        template <typename CharT>
        constexpr explicit stop_cond(
            std::basic_string_view<CharT> view) noexcept(true)
            : pattern(static_cast<const unsigned char*>(
                          static_cast<const void*>(view.data())),
                      view.size()) {}
        template <typename CharT, std::size_t Size>
        constexpr explicit stop_cond(const CharT (&s)[Size]) noexcept(true)
            : pattern(static_cast<const unsigned char*>(
                          static_cast<const void*>(s)),
                      Size - 1) {}

        constexpr std::size_t
        operator()(std::basic_string_view<unsigned char> str) noexcept(true) {
            std::size_t r = str.npos;
            return r = str.find(pattern),
                   r != str.npos ? r + pattern.size() : r;
        }

        constexpr std::size_t extend_size() noexcept(true) { return 128; }
    };

    struct stop_cond_char {
        unsigned char const c;

        template <typename CharT>
        constexpr explicit stop_cond_char(
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

        constexpr std::size_t extend_size() noexcept(true) { return 128; }
    };

    template <typename T>
    constexpr static decltype(auto) make_stop_cond(T&& t) noexcept(true) {
        if constexpr (std::is_constructible_v<stop_cond_char, T&&>) {
            return stop_cond_char(std::forward<T>(t));
        } else if constexpr (std::is_constructible_v<stop_cond, T&&>) {
            return stop_cond(std::forward<T>(t));
        } else {
            return std::forward<T>(t);
        }
    }
};
}  // namespace chx::net::detail::tags

namespace chx::net::ip::detail::tags {
struct simple_read {};
struct simple_write {};
struct readv {};
struct writev {};
struct connect2 {};
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
    template <typename Socket, typename StopCond, typename CompletionToken>
    decltype(auto) operator()(io_context*, Socket*, StopCond&&,
                              CompletionToken&&);
};

template <typename T> struct fill_iov_made : std::false_type {};
template <> struct fill_iov_made<std::vector<struct iovec>> : std::true_type {};
template <std::size_t N>
struct fill_iov_made<std::array<struct iovec, N>> : std::true_type {};

template <typename Socket, typename ConstBufferSequence,
          typename CompletionToken>
auto chx::net::detail::async_operation<chx::net::ip::detail::tags::writev>::
operator()(io_context* ctx, Socket* sock,
           ConstBufferSequence&& const_buffer_sequence,
           CompletionToken&& completion_token) -> decltype(auto) {
    io_context::task_t* task = ctx->acquire();
    if constexpr (!fill_iov_made<std::decay_t<ConstBufferSequence>>::value) {
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
            std::size_t iovec_len =
                std::min(std::distance(const_buffer_sequence.begin(),
                                       const_buffer_sequence.end()),
                         1024);
            std::vector<struct iovec> iovec_vec(iovec_len);
            auto iterator = const_buffer_sequence.begin();
            for (auto& iov : iovec_vec) {
                iov = detail::to_iovec_const(const_buffer(*(iterator++)));
            }
            sqe = ctx->get_sqe(task);
            io_uring_prep_writev(sqe, sock->native_handler(), iovec_vec.data(),
                                 iovec_vec.size(), 0);
            ctx->submit();
        }
    } else {
        io_uring_sqe* sqe = ctx->get_sqe(task);
        io_uring_prep_writev(
            sqe, sock->native_handler(), const_buffer_sequence.data(),
            std::min(const_buffer_sequence.size(), std::size_t{1024}), 0);
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
    using operation_type = decltype(tags::read_until::operation(
        *sock, std::forward<DynamicBuffer>(dynamic_buffer),
        tags::read_until::make_stop_cond(std::forward<StopCond>(stop_cond))));
    return async_combine<const std::error_code&, std::size_t>(
        *ctx, std::forward<CompletionToken>(completion_token),
        type_identity<operation_type>(), *sock,
        std::forward<DynamicBuffer>(dynamic_buffer),
        tags::read_until::make_stop_cond(std::forward<StopCond>(stop_cond)));
}
template <typename Socket, typename StopCond, typename CompletionToken>
decltype(auto)
chx::net::detail::async_operation<chx::net::detail::tags::read_until>::
operator()(io_context* ctx, Socket* sock, StopCond&& stop_cond,
           CompletionToken&& completion_token) {
    using operation_type = decltype(tags::read_until::operation(
        *sock,
        tags::read_until::make_stop_cond(std::forward<StopCond>(stop_cond))));
    return async_combine<
        const std::error_code&,
        std::pair<typename std::decay_t<StopCond>::container_type,
                  std::size_t>>(
        *ctx, std::forward<CompletionToken>(completion_token),
        type_identity<operation_type>(), *sock,
        tags::read_until::make_stop_cond(std::forward<StopCond>(stop_cond)));
}

template <>
struct chx::net::detail::async_operation<chx::net::ip::detail::tags::connect2> {
    template <typename GeneratedCompletionToken>
    struct c3 : GeneratedCompletionToken {
        union {
            struct sockaddr_in in4;
            struct sockaddr_in6 in6;
        } st = {};
        template <typename GCT>
        c3(const sockaddr_in& in4, GCT&& gct)
            : GeneratedCompletionToken(std::forward<GCT>(gct)) {
            st.in4 = in4;
        }
        template <typename GCT>
        c3(const sockaddr_in6& in6, GCT&& gct)
            : GeneratedCompletionToken(std::forward<GCT>(gct)) {
            st.in6 = in6;
        }
    };
    template <typename SockAddr, typename GeneratedCompletionToken>
    c3(const SockAddr&, GeneratedCompletionToken&&)
        -> c3<std::remove_reference_t<GeneratedCompletionToken>>;

    template <typename Protocol, typename BindCompletionToken> struct c2 {
        ip::basic_endpoint<Protocol> endpoint;
        BindCompletionToken bind_completion_token;
        int fd;

        io_context::task_t* task;

        using attribute_type = attribute<async_token>;

        template <typename P, typename BCT>
        c2(const ip::basic_endpoint<P>& ep, BCT&& bct, int f)
            : endpoint(ep), bind_completion_token(std::forward<BCT>(bct)),
              fd(f) {}

        template <typename FinalFunctor>
        decltype(auto) generate_token(io_context::task_t* t,
                                      FinalFunctor&& final_functor) {
            task = t;
            if (endpoint.address().is_v4()) {
                return c3(endpoint.sockaddr_in(),
                          async_token_generate(
                              t, std::forward<FinalFunctor>(final_functor),
                              std::forward<BindCompletionToken>(
                                  bind_completion_token)));
            } else {
                return c3(endpoint.sockaddr_in6(),
                          async_token_generate(
                              t, std::forward<FinalFunctor>(final_functor),
                              std::forward<BindCompletionToken>(
                                  bind_completion_token)));
            }
        }

        template <typename TypeIdentity>
        decltype(auto) get_init(TypeIdentity ti) {
            auto* sqe = task->get_associated_io_context().get_sqe(task);
            auto* d = static_cast<typename TypeIdentity::type*>(
                task->get_underlying_data());
            io_uring_prep_connect(sqe, fd, (const struct sockaddr*)&d->st,
                                  endpoint.address().is_v4()
                                      ? sizeof(sockaddr_in)
                                      : sizeof(sockaddr_in6));
            return async_token_init(
                ti, std::forward<BindCompletionToken>(bind_completion_token));
        }
    };
    template <typename Protocol, typename BindCompletionToken>
    c2(const ip::basic_endpoint<Protocol>&, BindCompletionToken&&, int)
        -> c2<Protocol, BindCompletionToken&&>;

    template <typename CompletionToken>
    decltype(auto) operator()(io_context* ctx,
                              CompletionToken&& completion_token) {
        auto* task = ctx->acquire();
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) mutable -> int {
                    token(self->__M_ec);
                    return 0;
                },
                completion_token)),
            completion_token);
    }
};
