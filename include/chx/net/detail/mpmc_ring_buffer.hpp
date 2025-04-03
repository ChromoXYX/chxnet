#pragma once

#include <memory>
#include <atomic>
#include "./noncopyable.hpp"

namespace chx::net::detail {
template <typename T, std::size_t Cap> struct mpmc_ring_buffer {
    CHXNET_NONCOPYABLE;
    CHXNET_NONMOVEABLE;

    struct slot {
        std::atomic_size_t seq;
        T t = {};
    };
    std::unique_ptr<slot[]> slots;

    mpmc_ring_buffer() : slots(std::make_unique<slot[]>(Cap)) {
        for (std::size_t i = 0; i < Cap; ++i) {
            slots[i].seq = i;
        }
    }

    alignas(64) std::atomic_size_t read_head = {0};
    alignas(64) std::atomic_size_t write_head = {0};

    T pop() noexcept(true) {
        std::atomic_thread_fence(std::memory_order_acquire);
        std::size_t read = read_head.load(std::memory_order_acquire);
        unsigned backoff = 1;
        for (;;) {
            slot* slot = &slots[read % Cap];
            std::size_t seq = slot->seq.load(std::memory_order_acquire);
            if (seq < read + 1) {
                // empty
                return T{};
            }
            if (seq == read + 1) {
                // hit
                if (read_head.compare_exchange_weak(
                        read, read + 1, std::memory_order_acq_rel)) {
                    break;
                }
                if (backoff < 1024) {
                    backoff *= 2;
                }
                for (unsigned i = 0; i < backoff; ++i) {
                    std::atomic_thread_fence(std::memory_order_relaxed);
                }
            } else {
                read = read_head.load(std::memory_order_relaxed);
                backoff = 1;
            }
        }
        slot* slot = &slots[read % Cap];
        auto t = std::move(slot->t);
        std::atomic_thread_fence(std::memory_order_release);
        slot->seq.store(read + Cap, std::memory_order_release);
        return std::move(t);
    }

    bool push(T t) noexcept(true) {
        std::atomic_thread_fence(std::memory_order_acquire);
        std::size_t write = write_head.load(std::memory_order_acquire);
        unsigned backoff = 1;
        for (;;) {
            slot* slot = &slots[write % Cap];
            std::size_t seq = slot->seq.load(std::memory_order_acquire);
            if (seq < write) {
                // full
                return false;
            }
            if (seq == write) {
                if (write_head.compare_exchange_weak(
                        write, write + 1, std::memory_order_acq_rel)) {
                    break;
                }
                if (backoff < 1024) {
                    backoff *= 2;
                }
                for (unsigned i = 0; i < backoff; ++i) {
                    std::atomic_thread_fence(std::memory_order_relaxed);
                }
            } else {
                write = write_head.load(std::memory_order_relaxed);
                backoff = 1;
            }
        }
        slot* slot = &slots[write % Cap];
        slot->t = std::move(t);
        std::atomic_thread_fence(std::memory_order_release);
        slot->seq.store(write + 1, std::memory_order_release);
        return true;
    }
};
}  // namespace chx::net::detail
