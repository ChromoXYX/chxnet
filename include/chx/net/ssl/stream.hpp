#pragma once

#include "../tcp.hpp"
#include "./context.hpp"
#include "../async_write_sequence_exactly.hpp"

#include <sys/epoll.h>

namespace chx::net::ssl {
namespace detail {
class bad_meth : public exception {
  public:
    using exception::exception;
};

template <typename Stream, typename SSLOperation, typename CntlType>
struct ssl_poll;

struct ssl_deleter {
    void operator()(SSL* ssl) noexcept(true) { SSL_free(ssl); }
};
}  // namespace detail

class bad_ssl_socket : public exception {
  public:
    using exception::exception;
};

template <typename Socket> class stream : public Socket {
    template <typename S, typename SSLOperation, typename CntlType>
    friend struct detail::ssl_poll;
    template <typename Tag> friend struct net::detail::async_operation;

    context* __M_context = nullptr;
    std::unique_ptr<SSL, detail::ssl_deleter> __M_ssl;

    void set_nonblock() {
        if (::fcntl(Socket::native_handler(), F_SETFL,
                    fcntl(Socket::native_handler(), F_GETFL, 0) | O_NONBLOCK) ==
            -1) {
            __CHXNET_THROW_WITH(errno, bad_ssl_socket);
        }
    }
    void set_ssl(context::method meth) {
        __M_ssl.reset(SSL_new(__M_context->native_handler()));
        BIO* bio;
        if (!get_associated_SSL()) {
            goto error;
        }
        if (SSL_set_fd(get_associated_SSL(), Socket::native_handler()) != 1) {
            goto error;
        }
        if (meth == context::method::tls_server) {
            SSL_set_accept_state(get_associated_SSL());
        } else {
            SSL_set_connect_state(get_associated_SSL());
        }
        bio = BIO_new(BIO_s_socket());
        if (!bio) {
            goto error;
        }
        if (BIO_set_fd(bio, Socket::native_handler(), BIO_NOCLOSE) != 1) {
            goto error;
        }
        SSL_set_bio(get_associated_SSL(), bio, bio);
        return;
    error:
        __CHXNET_THROW_STR_WITH(detail::last_error(), bad_ssl_socket);
    }

  public:
    using attribute_type = attribute<net::detail::no_short_write>;

    template <typename... Args>
    stream(context& ssl_context, Args&&... args)
        : ip::tcp::socket(std::forward<Args>(args)...),
          __M_context(&ssl_context) {
        set_nonblock();
        set_ssl(get_associated_ssl_context().get_method());
    }
    stream(stream&& other) noexcept(true) = default;
    ~stream() = default;

    constexpr context& get_associated_ssl_context() noexcept(true) {
        return *__M_context;
    }
    SSL* get_associated_SSL() noexcept(true) { return __M_ssl.get(); }
    constexpr io_context& get_associated_io_context() const noexcept(true) {
        return Socket::get_associated_io_context();
    }
    constexpr int native_handler() const noexcept(true) {
        return Socket::native_handler();
    }
    constexpr Socket& lower_layer() noexcept(true) {
        return static_cast<Socket&>(*this);
    }

    template <typename CompletionToken>
    decltype(auto) async_do_handshake(CompletionToken&& completion_token);
    template <typename CompletionToken>
    decltype(auto) async_shutdown(CompletionToken&& completion_token);

    template <typename ConstBuffer, typename CompletionToken>
    decltype(auto) async_write_some(
        ConstBuffer&& buffer, CompletionToken&& completion_token,
        net::detail::sfinae_placeholder<
            std::enable_if_t<net::detail::is_const_buffer<ConstBuffer>::value>>
            _ = net::detail::sfinae);
    template <typename MutableBuffer, typename CompletionToken>
    decltype(auto)
    async_read_some(MutableBuffer&& mutable_buffer,
                    CompletionToken&& completion_token,
                    net::detail::sfinae_placeholder<std::enable_if_t<
                        net::detail::is_mutable_buffer<MutableBuffer>::value>>
                        _ = net::detail::sfinae);

    template <typename IovArr, typename CompletionToken>
    decltype(auto) async_write_some(
        IovArr&& iov_arr, CompletionToken&& completion_token,
        net::detail::sfinae_placeholder<
            std::enable_if_t<!net::detail::is_const_buffer<IovArr>::value>>
            _ = net::detail::sfinae);
};

template <typename Socket> struct is_ssl_stream : std::false_type {};
template <typename Socket>
struct is_ssl_stream<stream<Socket>> : std::true_type {};
}  // namespace chx::net::ssl

#include "./impl/do_handshake.ipp"
#include "./impl/shutdown.ipp"
#include "./impl/write.ipp"
#include "./impl/read.ipp"
#include "./impl/write_seq.ipp"
