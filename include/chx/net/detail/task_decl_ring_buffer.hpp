#pragma once

#include "../task_decl.hpp"

namespace chx::net::detail {
template <std::size_t Capacity> struct task_decl_ring_buffer {
    task_decl_ring_buffer()
        : c(std::make_unique<std::unique_ptr<task_decl>[]>(Capacity)) {}

    std::unique_ptr<std::unique_ptr<task_decl>[]> c;
    std::size_t i = 0, j = 0;

    bool push(std::unique_ptr<task_decl> ptr) noexcept(true) {
        std::size_t next = (j + 1) % Capacity;
        if (next == i) {
            return false;
        }
        c[j] = std::move(ptr);
        j = next;
        return true;
    }

    constexpr task_decl* pop() noexcept(true) {
        if (i == j) {
            return nullptr;
        }
        task_decl* r = c[i].release();
        i = (i + 1) % Capacity;
        return r;
    }
};
}  // namespace chx::net::detail
