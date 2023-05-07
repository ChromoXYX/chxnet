#pragma once

#include "../error_code.hpp"

#include <openssl/err.h>

namespace chx::net::ssl {
inline std::error_category& error_category() noexcept(true) {
    class __category : public std::error_category {
      public:
        virtual const char* name() const noexcept(true) override {
            return "chxnet.ssl error_category";
        }

        virtual std::error_condition default_error_condition(int ev) const
            noexcept(true) override {
            return std::error_condition(ev, ssl::error_category());
        }

        virtual bool equivalent(const std::error_code& ec, int ev) const
            noexcept(true) override {
            return *this == ec.category() && static_cast<int>(ec.value()) == ev;
        }

        virtual std::string message(int ev) const override {
            char buf[128] = {};
            ERR_error_string_n(ev, buf, sizeof(buf));
            return buf;
        }
    };
    static __category c;
    return c;
}

namespace detail {
inline std::error_code make_ssl_ec(int value) noexcept(true) {
    return net::detail::make_ec(value, ssl::error_category());
}
}  // namespace detail
}  // namespace chx::net::ssl
