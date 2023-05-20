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
template <typename Stream> struct meth;
template <typename Stream> const BIO_METHOD* bio_custom_meth();

struct ssl_deleter {
    void operator()(SSL* ssl) noexcept(true) { SSL_free(ssl); }
};
}  // namespace detail

class bad_ssl_socket : public exception {
  public:
    using exception::exception;
};

template <typename Socket> class stream : public Socket {
    template <typename S> friend struct detail::meth;
    template <typename S, typename SSLOperation> friend struct detail::ssl_poll;
    template <typename Tag> friend struct net::detail::async_operation;

    context* __M_context = nullptr;
    std::unique_ptr<SSL, detail::ssl_deleter> __M_ssl;
    long __M_num = 0;

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
        bio = BIO_new(detail::bio_custom_meth<stream>());
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
    stream(context& ssl_context, Args&&... args)
        : ip::tcp::socket(std::forward<Args>(args)...),
          __M_context(&ssl_context) {
        set_nonblock();
        set_ssl(get_associated_ssl_context().get_method());
    }
    stream(stream&& other) noexcept(true)
        : ip::tcp::socket(std::move(other)), __M_context(other.__M_context),
          __M_ssl(std::move(other.__M_ssl)),
          __M_num(std::exchange(other.__M_num, 0)) {
        if (__M_ssl) {
            auto* bio = SSL_get_wbio(get_associated_SSL());
            if (bio) {
                BIO_set_data(bio, this);
            }
        }
    }
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
};
}  // namespace chx::net::ssl

#include "./impl/meth.ipp"
#include "./impl/do_handshake.ipp"
#include "./impl/shutdown.ipp"
#include "./impl/write.ipp"
#include "./impl/read.ipp"
