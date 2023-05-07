#pragma once

#include "../stream.hpp"
#include "../context.hpp"

#include <linux/tls.h>
#include <sys/poll.h>

namespace chx::net::ssl::detail {
template <typename Stream> struct meth {
    static bool read_valid(int fd) noexcept(true) {
        struct pollfd pfd = {};
        pfd.fd = fd;
        pfd.events = POLLIN;
        if (::poll(&pfd, 1, 0) != -1) {
            if (pfd.revents & POLLIN) {
                return true;
            } else {
                errno = EWOULDBLOCK;
            }
        }
        return false;
    }
    static bool write_valid(int fd) noexcept(true) {
        struct pollfd pfd = {};
        pfd.fd = fd;
        pfd.events = POLLOUT;
        if (::poll(&pfd, 1, 0) != -1) {
            if (pfd.revents & POLLOUT) {
                return true;
            } else {
                errno = EWOULDBLOCK;
            }
        }
        return false;
    }

    static int ktls_read_record(int fd, void* buf, size_t sz);
    static int ktls_send_ctrl_message(int fd, unsigned char record_type,
                                      const void* data, size_t length);

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
const BIO_METHOD* chx::net::ssl::detail::bio_custom_meth() {
    static const BIO_METHOD* impl = meth<Stream>::create_meth();
    return impl;
}

template <typename Stream>
BIO_METHOD* chx::net::ssl::detail::meth<Stream>::create_meth() {
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
int chx::net::ssl::detail::meth<Stream>::ktls_read_record(int fd, void* buf,
                                                          size_t sz) {
    struct msghdr msg;
    struct cmsghdr* cmsg;
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(unsigned char))];
    } cmsgbuf;
    struct iovec msg_iov;
    int ret;
    unsigned char* p = (unsigned char*)buf;
    const size_t prepend_length = SSL3_RT_HEADER_LENGTH;

    if (sz < prepend_length + EVP_GCM_TLS_TAG_LEN) {
        errno = EINVAL;
        return -1;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_control = cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);

    msg_iov.iov_base = p + prepend_length;
    msg_iov.iov_len = sz - prepend_length - EVP_GCM_TLS_TAG_LEN;
    msg.msg_iov = &msg_iov;
    msg.msg_iovlen = 1;

    ret = recvmsg(fd, &msg, 0);
    if (ret < 0)
        return ret;

    if (msg.msg_controllen > 0) {
        cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg->cmsg_type == TLS_GET_RECORD_TYPE) {
            p[0] = *((unsigned char*)CMSG_DATA(cmsg));
            p[1] = TLS1_2_VERSION_MAJOR;
            p[2] = TLS1_2_VERSION_MINOR;
            /* returned length is limited to msg_iov.iov_len above */
            p[3] = (ret >> 8) & 0xff;
            p[4] = ret & 0xff;
            ret += prepend_length;
        }
    }

    return ret;
}

template <typename Stream>
int chx::net::ssl::detail::meth<Stream>::ktls_send_ctrl_message(
    int fd, unsigned char record_type, const void* data, size_t length) {
    struct msghdr msg;
    int cmsg_len = sizeof(record_type);
    struct cmsghdr* cmsg;
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(unsigned char))];
    } cmsgbuf;
    struct iovec msg_iov; /* Vector of data to send/receive into */

    memset(&msg, 0, sizeof(msg));
    msg.msg_control = cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_TLS;
    cmsg->cmsg_type = TLS_SET_RECORD_TYPE;
    cmsg->cmsg_len = CMSG_LEN(cmsg_len);
    *((unsigned char*)CMSG_DATA(cmsg)) = record_type;
    msg.msg_controllen = cmsg->cmsg_len;

    msg_iov.iov_base = (void*)data;
    msg_iov.iov_len = length;
    msg.msg_iov = &msg_iov;
    msg.msg_iovlen = 1;

    return sendmsg(fd, &msg, 0);
}

template <typename Stream>
int chx::net::ssl::detail::meth<Stream>::sock_read(BIO* b, char* out,
                                                   int outl) {
    int ret = 0;

    if (out != NULL) {
        errno = 0;
        int fd = BIO_get_fd(b, nullptr);
        if (!read_valid(fd)) {
            ret = -1;
        } else {
#ifndef OPENSSL_NO_KTLS
            if (BIO_get_ktls_recv(b))
                ret = ktls_read_record(fd, out, outl);
            else
#endif
                ret = read(fd, out, outl);
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
int chx::net::ssl::detail::meth<Stream>::sock_write(BIO* b, const char* in,
                                                    int inl) {
    int ret = 0;

    errno = 0;
    int fd = BIO_get_fd(b, nullptr);
    if (!write_valid(fd)) {
        ret = -1;
    } else {
#ifndef OPENSSL_NO_KTLS
        if (BIO_test_flags(b, 0x1000)) {
            unsigned char record_type =
                (static_cast<Stream*>(BIO_get_data(b)))->__M_num;
            ret = ktls_send_ctrl_message(fd, record_type, in, inl);
            if (ret >= 0) {
                ret = inl;
                BIO_clear_flags(b, 0x1000);
            }
        } else
#endif
            ret = write(fd, in, inl);
    }
    BIO_clear_retry_flags(b);
    if (ret <= 0) {
        if (BIO_sock_should_retry(ret))
            BIO_set_retry_write(b);
    }
    return ret;
}

template <typename Stream>
long chx::net::ssl::detail::meth<Stream>::sock_ctrl(BIO* b, int cmd, long num,
                                                    void* ptr) {
    if (cmd == 74) {
        BIO_set_flags(b, 0x1000);
        Stream* ptr = static_cast<Stream*>(BIO_get_data(b));
        ptr->__M_num = num;
        return 0;
    } else {
        return BIO_meth_get_ctrl(BIO_s_socket())(b, cmd, num, ptr);
    }
}

template <typename Stream>
int chx::net::ssl::detail::meth<Stream>::sock_new(BIO* bi) {
    BIO_set_init(bi, 0);
    BIO_set_fd(bi, 0, 0);
    BIO_set_data(bi, nullptr);
    BIO_set_flags(bi, 0);
    return 1;
}

template <typename Stream>
int chx::net::ssl::detail::meth<Stream>::sock_destroy(BIO* a) {
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
int chx::net::ssl::detail::meth<Stream>::sock_puts(BIO* b, const char* str) {
    return sock_write(b, str, std::strlen(str));
}
