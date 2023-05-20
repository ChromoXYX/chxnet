#pragma once

#include "../stream.hpp"

namespace chx::net::ssl::detail {
template <typename Stream> struct no_ktls_meth {
    static int sock_read(BIO* b, char* buf, int sz);
    static int sock_write(BIO* b, const char* buf, int sz);
    static int sock_new(BIO* b);
    static int sock_destroy(BIO* b);
    static long sock_ctrl(BIO* b, int cmd, long num, void* ptr);
    static int sock_puts(BIO* b, const char* str);

    static inline int sock_read_conv(BIO* bio, char* data, size_t datal,
                                     size_t* readbytes) {
        int ret;
        if (datal > INT_MAX)
            datal = INT_MAX;
        ret = sock_read(bio, data, (int)datal);
        if (ret <= 0) {
            *readbytes = 0;
            return ret;
        }
        *readbytes = (size_t)ret;
        return 1;
    }
    static inline int sock_write_conv(BIO* bio, const char* data, size_t datal,
                                      size_t* written) {
        int ret;
        if (datal > INT_MAX)
            datal = INT_MAX;
        ret = sock_write(bio, data, (int)datal);
        if (ret <= 0) {
            *written = 0;
            return ret;
        }
        *written = (size_t)ret;
        return 1;
    }

    static BIO_METHOD* create_meth();
};
}  // namespace chx::net::ssl::detail

template <typename Stream>
const BIO_METHOD* chx::net::ssl::detail::bio_custom_meth_without_ktls() {
    static const BIO_METHOD* impl = no_ktls_meth<Stream>::create_meth();
    return impl;
}

template <typename Stream>
BIO_METHOD* chx::net::ssl::detail::no_ktls_meth<Stream>::create_meth() {
    BIO_METHOD* method =
        BIO_meth_new(BIO_get_new_index(), "chxnet custom meth");
    if (!method) {
        __CHXNET_THROW_CSTR_WITH(last_error(), bad_meth);
    }
    BIO_meth_set_create(method, sock_new);
    BIO_meth_set_destroy(method, sock_destroy);
    BIO_meth_set_ctrl(method, sock_ctrl);
    BIO_meth_set_read(method, sock_read);
    BIO_meth_set_read_ex(method, sock_read_conv);
    BIO_meth_set_write(method, sock_write);
    BIO_meth_set_write_ex(method, sock_write_conv);
    BIO_meth_set_puts(method, sock_puts);
    return method;
}

template <typename Stream>
int chx::net::ssl::detail::no_ktls_meth<Stream>::sock_read(BIO* b, char* out,
                                                           int outl) {
    int ret = 0;

    if (out != NULL) {
        errno = 0;

        auto* self = static_cast<Stream*>(BIO_get_data(b));
        std::string& in_buf_ref = self->__M_in_buf;
        if (!in_buf_ref.empty()) {
            if (in_buf_ref.size() < outl) {
                ret = in_buf_ref.size();
                memcpy(out, in_buf_ref.c_str(), in_buf_ref.size());
                in_buf_ref.clear();
            } else {
                ret = outl;
                memcpy(out, in_buf_ref.c_str(), outl);
                try {
                    in_buf_ref.erase(0, outl);
                } catch (const std::exception& ex) {
                    in_buf_ref.clear();
                    errno = errc::internal_error;
                    ret = -1;
                }
            }
        } else {
            ret = -1;
            errno = EAGAIN;
        }

        BIO_clear_retry_flags(b);
        if (ret <= 0) {
            if (BIO_sock_should_retry(ret))
                BIO_set_retry_read(b);
            else if (ret == 0)
                BIO_set_flags(b, BIO_FLAGS_IN_EOF);
        }
    }
    return ret;
}

template <typename Stream>
int chx::net::ssl::detail::no_ktls_meth<Stream>::sock_write(BIO* b,
                                                            const char* in,
                                                            int inl) {
    int ret = 0;

    errno = 0;
    auto* self = static_cast<Stream*>(BIO_get_data(b));
    self->__M_out_buf.append(in, inl);
    ret = inl;

    BIO_clear_retry_flags(b);
    if (ret <= 0) {
        if (BIO_sock_should_retry(ret))
            BIO_set_retry_write(b);
    }
    return ret;
}

template <typename Stream>
long chx::net::ssl::detail::no_ktls_meth<Stream>::sock_ctrl(BIO* b, int cmd,
                                                            long num,
                                                            void* ptr) {
    if (cmd == 74) {
        return -1;
    } else {
        return BIO_meth_get_ctrl(BIO_s_socket())(b, cmd, num, ptr);
    }
}

template <typename Stream>
int chx::net::ssl::detail::no_ktls_meth<Stream>::sock_new(BIO* bi) {
    BIO_set_init(bi, 0);
    BIO_set_fd(bi, 0, 0);
    BIO_set_data(bi, nullptr);
    BIO_set_flags(bi, 0);
    return 1;
}

template <typename Stream>
int chx::net::ssl::detail::no_ktls_meth<Stream>::sock_destroy(BIO* a) {
    if (a == NULL)
        return 0;
    if (BIO_get_shutdown(a)) {
        if (BIO_get_init(a)) {
            BIO_closesocket(BIO_get_fd(a, nullptr));
        }
        BIO_set_init(a, 0);
        BIO_set_flags(a, 0);
    }
    return 1;
}

template <typename Stream>
int chx::net::ssl::detail::no_ktls_meth<Stream>::sock_puts(BIO* b,
                                                           const char* str) {
    return sock_write(b, str, std::strlen(str));
}
