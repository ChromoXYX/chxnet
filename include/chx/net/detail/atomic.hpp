#pragma once

#include <atomic>
#include "../error_code.hpp"

namespace chx::net::detail {
template <typename T> struct atomic {
    T value;

    T load(std::memory_order m) {
        T result;
        switch (m) {
        case std::memory_order::relaxed: {
            __atomic_load(&value, &result, __ATOMIC_RELAXED);
            break;
        }
        case std::memory_order::consume: {
            __atomic_load(&value, &result, __ATOMIC_CONSUME);
            break;
        }
        case std::memory_order::acquire: {
            __atomic_load(&value, &result, __ATOMIC_ACQUIRE);
            break;
        }
        case std::memory_order::seq_cst: {
            __atomic_load(&value, &result, __ATOMIC_SEQ_CST);
            break;
        }
        default: {
            __CHXNET_THROW_EC(make_ec(errc::invalid_argument));
        }
        }
        return std::move(result);
    }

    void store(T desired, std::memory_order m) {
        switch (m) {
        case std::memory_order::relaxed: {
            __atomic_store(&value, &desired, __ATOMIC_RELAXED);
            break;
        }
        case std::memory_order::release: {
            __atomic_store(&value, &desired, __ATOMIC_RELEASE);
            break;
        }
        case std::memory_order::seq_cst: {
            __atomic_store(&value, &desired, __ATOMIC_SEQ_CST);
            break;
        }
        default: {
            __CHXNET_THROW_EC(make_ec(errc::invalid_argument));
        }
        }
    }
};
}  // namespace chx::net::detail
