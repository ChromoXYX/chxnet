#pragma once

#include <execinfo.h>
#include <string>
#include <cstdint>
#ifdef CHXNET_ENABLE_EXCEPTION_BACKTRACE
#include <boost/stacktrace.hpp>
#endif

namespace chx::net {
/**
 * @brief Base type of exceptions used in chxnet.
 *
 * @details If CHXNET_ENABLE_EXCEPTION_BACKTRACE is defined, backtrace
 * information will be generated when an exception is constructed.
 *
 */
class exception : public std::exception {
    std::string __M_msg;

#ifdef CHXNET_ENABLE_EXCEPTION_BACKTRACE
    boost::stacktrace::stacktrace __M_st;
#endif

  public:
    exception() {}
    exception(const exception&) = default;
    exception(exception&&) = default;

    exception(const std::string& msg) : __M_msg(msg) {}
    exception(const char* cmsg) : __M_msg(cmsg) {}

    const char* what() const noexcept(true) override { return __M_msg.c_str(); }
#ifdef CHXNET_ENABLE_EXCEPTION_BACKTRACE
    const boost::stacktrace::stacktrace& backtrace() const noexcept(true) {
        return __M_st;
    }
#endif
};
}  // namespace chx::net
