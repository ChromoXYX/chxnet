#pragma once

#include "../tcp.hpp"
#include "./context.hpp"

#include <sys/epoll.h>

namespace chx::net::ssl {
namespace detail {
class bad_meth : public exception {
  public:
    using exception::exception;
};

template <typename Stream, typename SSLOperation> struct ssl_poll;

template <typename Stream> struct no_ktls_meth;
template <typename Stream> const BIO_METHOD* bio_custom_meth_without_ktls();
template <typename Stream, typename SSLOperation> struct ssl_no_ktls;
template <typename Stream, typename SSLOperation> struct ssl_no_ktls_rw;

struct ssl_deleter {
    void operator()(SSL* ssl) noexcept(true) { SSL_free(ssl); }
};
}  // namespace detail

class bad_ssl_socket : public exception {
  public:
    using exception::exception;
};

template <typename Socket> class stream : public Socket {
    template <typename S, typename SSLOperation> friend struct detail::ssl_poll;
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
        __CHXNET_THROW_CSTR_WITH(detail::last_error(), bad_ssl_socket);
    }

  public:
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

    template <typename ConstBufferSequence, typename CompletionToken>
    [[deprecated("bad performance, use ktls instead")]] decltype(auto)
    async_write_some(
        ConstBufferSequence&& const_buffer_sequence,
        CompletionToken&& completion_token,
        net::detail::sfinae_placeholder<
            std::enable_if_t<is_const_buffer_sequence<
                std::remove_reference_t<ConstBufferSequence>>::value>>
            _ = net::detail::sfinae);
};

template <typename Socket> class stream_noktls : public Socket {
    template <typename S> friend struct detail::no_ktls_meth;
    template <typename Tag> friend struct net::detail::async_operation;
    template <typename S, typename R> friend struct detail::ssl_no_ktls;
    template <typename S, typename R> friend struct detail::ssl_no_ktls_rw;

    context* __M_context = nullptr;
    std::unique_ptr<SSL, detail::ssl_deleter> __M_ssl;

    std::string __M_in_buf;
    std::string __M_out_buf;
    inline static constexpr std::size_t read_buffer_max_size = 512;

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
        bio = BIO_new(detail::bio_custom_meth_without_ktls<stream_noktls>());
        if (!bio) {
            goto error;
        }
        if (BIO_set_fd(bio, Socket::native_handler(), BIO_NOCLOSE) != 1) {
            goto error;
        }
        BIO_set_data(bio, this);
        SSL_set_bio(get_associated_SSL(), bio, bio);
        return;
    error:
        __CHXNET_THROW_CSTR_WITH(detail::last_error(), bad_ssl_socket);
    }

  public:
    template <typename... Args>
    stream_noktls(context& ssl_context, Args&&... args)
        : ip::tcp::socket(std::forward<Args>(args)...),
          __M_context(&ssl_context) {
        set_ssl(get_associated_ssl_context().get_method());
    }
    stream_noktls(stream_noktls&& other) noexcept(true)
        : ip::tcp::socket(std::move(other)), __M_context(other.__M_context),
          __M_ssl(std::move(other.__M_ssl)),
          __M_in_buf(std::move(other.__M_in_buf)),
          __M_out_buf(std::move(other.__M_out_buf)) {
        if (__M_ssl) {
            auto* bio = SSL_get_wbio(get_associated_SSL());
            if (bio) {
                BIO_set_data(bio, this);
            }
        }
    }
    ~stream_noktls() = default;

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
};
}  // namespace chx::net::ssl

#include "./impl/no_ktls_meth.ipp"

#include "./impl/do_handshake.ipp"
#include "./impl/shutdown.ipp"
#include "./impl/write.ipp"
#include "./impl/read.ipp"

#include "./impl/no_ktls_handshake.ipp"
#include "./impl/no_ktls_read.ipp"
#include "./impl/no_ktls_write.ipp"
#include "./impl/no_ktls_shutdown.ipp"

#include "./impl/write_buffer_sequence.ipp"
