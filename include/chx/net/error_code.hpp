#pragma once

#include <cstring>
#include <system_error>

#include "./exception.hpp"

namespace chx::net {
using errc = std::errc;
using std::make_error_condition;

enum class additional_errc : int {
    internal_error = 1,
    socket_already_open = 2,
    eof = 3,
};
}  // namespace chx::net

namespace std {
template <>
struct is_error_condition_enum<::chx::net::additional_errc> : std::true_type {};
}  // namespace std

namespace chx::net {
inline std::error_category& additional_category() {
    class __category : public std::error_category {
      public:
        virtual const char* name() const noexcept(true) override {
            return "chxnet additional_category";
        }

        virtual std::error_condition default_error_condition(int ev) const
            noexcept(true) override {
            return std::error_condition(ev, net::additional_category());
        }

        virtual bool equivalent(const std::error_code& ec, int ev) const
            noexcept(true) override {
            return *this == ec.category() && static_cast<int>(ec.value()) == ev;
        }

        virtual std::string message(int ev) const override {
            switch (static_cast<additional_errc>(ev)) {
            case additional_errc::eof: {
                return "Encountered EOF";
            }
            case additional_errc::internal_error: {
                return "chxnet internal error";
            }
            case additional_errc::socket_already_open: {
                return "Socket already open";
            }
            default: {
                return ::strerror(ev);
            }
            }
        }
    } static __c;

    return __c;
}
inline std::error_condition make_error_condition(additional_errc e) {
    return {static_cast<int>(e), additional_category()};
}

inline std::error_code
make_ec(int code,
        const std::error_category& c = std::generic_category()) noexcept(true) {
    return {code, c};
}
inline std::error_code make_ec(errc code) noexcept(true) {
    return {static_cast<int>(code), std::generic_category()};
}
inline std::error_code make_ec(additional_errc code) noexcept(true) {
    return {static_cast<int>(code), additional_category()};
}

inline void assign_ec(
    std::error_code& ec, int code,
    const std::error_category& c = std::generic_category()) noexcept(true) {
    ec.assign(code, c);
}
inline void assign_ec(std::error_code& ec, errc code) noexcept(true) {
    ec.assign(static_cast<int>(code), std::generic_category());
}
inline void assign_ec(std::error_code& ec,
                      additional_errc code) noexcept(true) {
    ec.assign(static_cast<int>(code), additional_category());
}
}  // namespace chx::net

#define __CHXNET_MAKE_QUOTE_IMPL(s) #s
#define __CHXNET_MAKE_QUOTE(s) __CHXNET_MAKE_QUOTE_IMPL(s)

#define __CHXNET_MAKE_EX_WITH(v, type)                                         \
    type(v + " at " __FILE__ ":" __CHXNET_MAKE_QUOTE(__LINE__))
#define __CHXNET_MAKE_EX_CODE_WITH(code, type)                                 \
    __CHXNET_MAKE_EX_WITH(::chx::net::make_ec(code).message(), type)
#define __CHXNET_MAKE_EX_CODE(code)                                            \
    __CHXNET_MAKE_EX_CODE_WITH(code, ::chx::net::exception)
#define __CHXNET_MAKE_EX_CSTR_WITH(cstr, type)                                 \
    type(cstr " at " __FILE__ ":" __CHXNET_MAKE_QUOTE(__LINE__))
#define __CHXNET_MAKE_EX_CSTR(cstr)                                            \
    __CHXNET_MAKE_EX_CSTR_WITH(cstr, ::chx::net::exception)

#define __CHXNET_THROW_WITH(code, type)                                        \
    throw __CHXNET_MAKE_EX_WITH(::chx::net::make_ec(code).message(), type)
#define __CHXNET_THROW(code) __CHXNET_THROW_WITH(code, ::chx::net::exception)
#define __CHXNET_THROW_EC_WITH(ec, type)                                       \
    throw __CHXNET_MAKE_EX_WITH(ec.message(), type)
#define __CHXNET_THROW_EC(ec) __CHXNET_THROW_EC_WITH(ec, ::chx::net::exception)
#define __CHXNET_THROW_STR_WITH(cstr, type)                                    \
    throw __CHXNET_MAKE_EX_WITH(std::string(cstr), type)
#define __CHXNET_THROW_STR(cstr)                                               \
    __CHXNET_THROW_STR_WITH(cstr, ::chx::net::exception)
#define __CHXNET_THROW_CSTR_WITH(cstr, type)                                   \
    throw __CHXNET_MAKE_EX_CSTR_WITH(cstr, type)
#define __CHXNET_THROW_CSTR(cstr)                                              \
    __CHXNET_THROW_CSTR_WITH(cstr, ::chx::net::exception)
