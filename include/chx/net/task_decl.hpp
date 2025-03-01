#pragma once

#ifndef CHXNET_TOKEN_STORAGE_SIZE
#define CHXNET_TOKEN_STORAGE_SIZE 48
#endif

#include "./detail/tracker.hpp"
#include "./detail/noncopyable.hpp"

#include <cstdint>
#include <liburing/io_uring.h>
#include <memory>

#include "./detail/basic_token_storage.hpp"

namespace chx::net {
class io_context;

template <std::size_t StorageSize = 48>
struct basic_task_decl
    : detail::enable_weak_from_this<basic_task_decl<StorageSize>> {
    CHXNET_NONCOPYABLE
    struct cancellation_controller_base {
        virtual void cancel(basic_task_decl*) = 0;
        virtual ~cancellation_controller_base() = default;
    };

    basic_task_decl(io_context* p) noexcept(true) : __M_ctx(p) {}

    io_context* __M_ctx = nullptr;

    std::uint64_t __M_additional = {};

    bool __M_notif = false;
    bool __M_persist = false;
    enum __CancelType : std::uint8_t {
        __CT_io_uring_based,
        __CT_invoke_cancel,
        __CT_no_cancel
    } __M_cancel_type = __CT_io_uring_based;

    union {
        std::int64_t __M_res = 0;
        io_uring_cqe* __M_cqe;
    };

    std::unique_ptr<cancellation_controller_base> __M_custom_cancellation;

    detail::basic_token_storage<int(basic_task_decl*),
                                CHXNET_TOKEN_STORAGE_SIZE,
                                alignof(std::max_align_t)>
        __M_token;

    void reset() {
        try {
            __M_additional = 0;
            __M_notif = false;
            __M_persist = false;
            __M_cancel_type = __CT_io_uring_based;

            __M_res = 0;

            __M_custom_cancellation.reset();
            this->renew();
            __M_token.destruct();
        } catch (const std::exception&) {
            rethrow_with_fatal(std::current_exception());
        }
    }

    constexpr io_context& get_associated_io_context() noexcept(true) {
        return *__M_ctx;
    }
    void* get_underlying_data() noexcept(true) {
        return __M_token.underlying_data();
    }
};

using task_decl = basic_task_decl<CHXNET_TOKEN_STORAGE_SIZE>;
}  // namespace chx::net
