#pragma once

#include <execinfo.h>
#include <string>
#include <cstdint>
#ifdef CHXNET_ENABLE_EXCEPTION_BACKTRACE
#include <exception>
#include <vector>
#endif

#define CHXNET_BACKTRACE_LEVEL 16

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
    std::vector<std::string> __M_bt;
#define __CHXNET_GENERATE_BT                                                   \
    {                                                                          \
        void* a[CHXNET_BACKTRACE_LEVEL];                                       \
        int sz = ::backtrace(a, CHXNET_BACKTRACE_LEVEL);                       \
        char** strs = ::backtrace_symbols(a, sz);                              \
        try {                                                                  \
            for (int i = 0; i < sz; ++i) {                                     \
                __M_bt.emplace_back(strs[i]);                                  \
            }                                                                  \
        } catch (...) {                                                        \
            ::free(strs);                                                      \
            std::rethrow_exception(std::current_exception());                  \
        }                                                                      \
        ::free(strs);                                                          \
    }
#else
#define __CHXNET_GENERATE_BT
#endif

  public:
    exception() { __CHXNET_GENERATE_BT; }
    exception(const exception&) = default;
    exception(exception&&) = default;

    exception(const std::string& msg) : __M_msg(msg) { __CHXNET_GENERATE_BT; }
    exception(const char* cmsg) : __M_msg(cmsg) { __CHXNET_GENERATE_BT; }

    const char* what() const noexcept(true) override { return __M_msg.c_str(); }
#ifdef CHXNET_ENABLE_EXCEPTION_BACKTRACE
    const std::vector<std::string>& backtrace() const noexcept(true) {
        return __M_bt;
    }
#endif
};
}  // namespace chx::net
