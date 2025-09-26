#pragma once

#ifndef CHXNET_TOKEN_STORAGE_SIZE
#define CHXNET_TOKEN_STORAGE_SIZE 56
#endif

#include <cstdint>
#include <liburing/io_uring.h>

#include "./detail/unique_ptr_std_layout.hpp"
#include "./detail/basic_token_storage.hpp"

namespace chx::net {
class io_context;

template <std::size_t StorageSize> struct basic_task_decl {
    detail::basic_token_storage<int(basic_task_decl*), StorageSize> __M_token;

    struct cancellation_controller_base {
        virtual void cancel(basic_task_decl*) = 0;
        virtual ~cancellation_controller_base() = default;

        virtual bool is_static() const noexcept(true) { return false; }
    };
    struct cancellation_controller_deleter
        : std::default_delete<cancellation_controller_base> {
        using std::default_delete<cancellation_controller_base>::operator=;
        void operator()(cancellation_controller_base* ptr) const {
            if (!ptr->is_static()) {
                std::default_delete<cancellation_controller_base>::operator()(
                    ptr);
            }
        }
    };

    basic_task_decl(io_context* p) noexcept(true) : __M_ctx(p) {
        static_assert(offsetof(basic_task_decl, __M_token) == 0);
    }
    basic_task_decl(const basic_task_decl&) = delete;

    io_context* __M_ctx = nullptr;

    union {
        std::uint64_t __M_additional_val = {};
        void* __M_additional_ptr;
    };
    union {
        std::uint64_t __M_additional_val2 = {};
        void* __M_additional_ptr2;
    };
    union {
        std::int64_t __M_res = 0;
        io_uring_cqe* __M_cqe;
    };

    bool __M_notif = false;
    bool __M_persist = false;

    enum __CancelType : std::uint8_t {
        __CT_io_uring_based,
        __CT_invoke_cancel,
        __CT_no_cancel
    } __M_cancel_type = __CT_io_uring_based;

    detail::unique_ptr_std_layout<cancellation_controller_base,
                                  cancellation_controller_deleter>
        __M_custom_cancellation;

    basic_task_decl* __M_prev = nullptr;
    basic_task_decl* __M_next = nullptr;

    void reset() {
        try {
            __M_additional_val = 0;
            __M_notif = false;
            __M_persist = false;
            __M_cancel_type = __CT_io_uring_based;

            __M_res = 0;

            __M_custom_cancellation.reset();
            if (this->__M_token) {
                this->__M_token.destruct();
            }
        } catch (const std::exception&) {
            rethrow_with_fatal(std::current_exception());
        }
    }

    constexpr io_context& get_associated_io_context() noexcept(true) {
        return *__M_ctx;
    }
    void* get_underlying_data() noexcept(true) {
        return this->__M_token.underlying_data();
    }
};

using task_decl = basic_task_decl<CHXNET_TOKEN_STORAGE_SIZE>;
}  // namespace chx::net
