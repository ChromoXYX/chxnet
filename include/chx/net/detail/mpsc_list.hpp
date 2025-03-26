#pragma once

#include <atomic>
#include <optional>

namespace chx::net::detail {
template <typename T> struct mpsc_list {
    struct node_type {
        std::optional<T> t;
        std::atomic<node_type*> next = {nullptr};
    };

    mpsc_list() {
        pop_point = new node_type{};
        push_point = pop_point;
    }
    ~mpsc_list() {
        while (pop()) {
        }
        delete push_point.exchange(nullptr);
    }

    node_type* pop_point;
    alignas(64) std::atomic<node_type*> push_point;

    std::optional<T> pop() {
        node_type* node = pop_point;
        node_type* next = node->next.load(std::memory_order_acquire);
        if (!next) {
            return std::nullopt;
        }
        auto t = std::move(next->t);
        pop_point = next;
        delete node;
        return std::move(t);
    }

    void push(T t) {
        node_type* node = new node_type{std::move(t)};
        node_type* prev_push_point =
            push_point.exchange(node, std::memory_order_acq_rel);
        prev_push_point->next.store(node, std::memory_order_release);
    }
};
}  // namespace chx::net::detail
