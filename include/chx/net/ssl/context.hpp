#pragma once

#include "../exception.hpp"
#include "../error_code.hpp"
#include "../detail/noncopyable.hpp"
#include "../detail/basic_token_storage.hpp"

#include <cassert>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace chx::net::ssl {
class bad_context : public net::exception {
  public:
    using exception::exception;
};

namespace detail {
inline std::string last_error() {
    char buf[128] = {};
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return {buf};
}
}  // namespace detail

class context : CHXNET_NONCOPYABLE {
    SSL_CTX* __M_ssl_ctx = nullptr;
    net::detail::basic_token_storage<std::string(std::size_t, int)>
        __M_passwd_fn;

    static int __passwd_cb(char* c, int sz, int p, void* u) {
        auto* self = static_cast<context*>(u);
        auto pw = self->__M_passwd_fn(static_cast<std::size_t>(sz), p);
        assert(pw.size() <= sz);
        strncpy(c, pw.c_str(), pw.size());
        return pw.size();
    }

  public:
    enum method {
        // tls,
        tls_server,
        tls_client,
        // sslv23 = tls,
        sslv23_server = tls_server,
        sslv23_client = tls_client,
    };
    enum filetype { pem, asn1 };
    enum protocol_version : unsigned short {
        tls1_1 = TLS1_1_VERSION,
        tls1_2 = TLS1_2_VERSION,
        tls1_3 = TLS1_3_VERSION
    };

    ~context() { SSL_CTX_free(__M_ssl_ctx); }

    context(method meth) : __M_meth(meth) {
        ERR_clear_error();
        switch (meth) {
        // case tls: {
        //     __M_ssl_ctx = SSL_CTX_new(TLS_method());
        //     break;
        // }
        case tls_server: {
            __M_ssl_ctx = SSL_CTX_new(TLS_server_method());
            break;
        }
        case tls_client: {
            __M_ssl_ctx = SSL_CTX_new(TLS_client_method());
            break;
        }
        default: {
            __CHXNET_THROW_WITH(EINVAL, bad_context);
        }
        }

        if (__M_ssl_ctx == nullptr) {
            __CHXNET_THROW_CSTR_WITH(detail::last_error(), bad_context);
        }
    }

    constexpr SSL_CTX* native_handler() noexcept(true) { return __M_ssl_ctx; }
    constexpr method get_method() noexcept(true) { return __M_meth; }

    void use_certificate_file(const char* cstr, filetype ft) {
        ERR_clear_error();
        int r = SSL_CTX_use_certificate_file(native_handler(), cstr,
                                             ft == pem ? SSL_FILETYPE_PEM
                                                       : SSL_FILETYPE_ASN1);
        if (r != 1) {
            __CHXNET_THROW_CSTR_WITH(detail::last_error(), bad_context);
        }
    }
    void use_PrivateKey_file(const char* cstr, filetype ft) {
        ERR_clear_error();
        int r = SSL_CTX_use_PrivateKey_file(native_handler(), cstr,
                                            ft == pem ? SSL_FILETYPE_PEM
                                                      : SSL_FILETYPE_ASN1);
        if (r != 1) {
            __CHXNET_THROW_CSTR_WITH(detail::last_error(), bad_context);
        }
    }
    void use_certificate_chain_file(const char* cstr) {
        ERR_clear_error();
        int r = SSL_CTX_use_certificate_chain_file(native_handler(), cstr);
        if (r != 1) {
            __CHXNET_THROW_CSTR_WITH(detail::last_error(), bad_context);
        }
    }

    void set_default_passwd_cb_userdata(void* user_data) noexcept(true) {
        SSL_CTX_set_default_passwd_cb_userdata(native_handler(), user_data);
    }
    void set_default_passwd_cb(pem_password_cb* cb) noexcept(true) {
        SSL_CTX_set_default_passwd_cb(native_handler(), cb);
    }
    template <typename PasswordFn>
    void set_default_passwd_cb(PasswordFn&& password_fn) {
        SSL_CTX_set_default_passwd_cb_userdata(native_handler(), this);
        SSL_CTX_set_default_passwd_cb(native_handler(), __passwd_cb);
    }

    std::uint64_t set_options(int option) noexcept(true) {
        return SSL_CTX_set_options(native_handler(), option);
    }
    std::uint64_t get_options() noexcept(true) {
        return SSL_CTX_get_options(native_handler());
    }
    std::uint64_t clear_options(int option) noexcept(true) {
        return SSL_CTX_clear_options(native_handler(), option);
    }

    void set_min_proto_version(protocol_version v) {
        ERR_clear_error();
        if (SSL_CTX_set_min_proto_version(native_handler(), v) == 0) {
            __CHXNET_THROW_CSTR_WITH(detail::last_error(), bad_context);
        }
    }
    void set_max_proto_version(protocol_version v) {
        ERR_clear_error();
        if (SSL_CTX_set_max_proto_version(native_handler(), v) == 0) {
            __CHXNET_THROW_CSTR_WITH(detail::last_error(), bad_context);
        }
    }

  private:
    method __M_meth;
};
}  // namespace chx::net::ssl
