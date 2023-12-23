#pragma once

#include "../io_context.hpp"

namespace chx::net::detail {
namespace tags {
struct anchor {};
}  // namespace tags

template <> struct async_operation<tags::anchor> {
    struct inner_anchor;
    struct outer_anchor;

    struct inner_anchor : CHXNET_NONCOPYABLE {
        io_context::task_t* task = nullptr;
        outer_anchor* outer = nullptr;

        constexpr inner_anchor(io_context::task_t* t,
                               outer_anchor* o) noexcept(true)
            : task(t), outer(o) {}
        inner_anchor(inner_anchor&& other) noexcept(true) {
            task = std::exchange(other.task, nullptr);
            outer = std::exchange(other.outer, nullptr);
            if (outer) {
                outer->inner = this;
            }
        }
        constexpr ~inner_anchor() noexcept(true) {
            if (outer) {
                outer->inner = nullptr;
                outer = nullptr;
            }
        }

        constexpr inner_anchor& operator=(inner_anchor&& other) noexcept(true) {
            if (this == &other) {
                return *this;
            }
            task = std::exchange(other.task, nullptr);
            outer = std::exchange(other.outer, nullptr);
            if (outer) {
                outer->inner = this;
            }
            return *this;
        }
    };

    struct outer_anchor : CHXNET_NONCOPYABLE {
        io_context::task_t* task = nullptr;
        inner_anchor* inner = nullptr;

        constexpr outer_anchor(io_context::task_t* t,
                               inner_anchor* i) noexcept(true)
            : task(t), inner(i) {}
        outer_anchor(outer_anchor&& other) noexcept(true) {
            task = std::exchange(other.task, nullptr);
            inner = std::exchange(other.inner, nullptr);
            if (inner) {
                inner->outer = this;
            }
        }
        constexpr ~outer_anchor() noexcept(true) {
            if (inner) {
                inner->outer = nullptr;
                inner = nullptr;
            }
        }

        constexpr outer_anchor& operator=(outer_anchor&& other) noexcept(true) {
            if (this == &other) {
                return *this;
            }
            task = std::exchange(other.task, nullptr);
            inner = std::exchange(other.inner, nullptr);
            if (inner) {
                inner->outer = this;
            }
            return *this;
        }
    };

    template <typename F> outer_anchor make_anchor(io_context* ctx, F&& f) {
        io_context::task_t* task = ctx->acquire();
        inner_anchor inner(task, nullptr);
        outer_anchor outer(task, &inner);
        inner.outer = &outer;

        task->__M_token.emplace(
            [inner = std::move(inner),
             f = std::forward<F>(f)](io_context::task_t* self) mutable {
                f(self, inner);
                return 0;
            });
        return std::move(outer);
    }
};
}  // namespace chx::net::detail