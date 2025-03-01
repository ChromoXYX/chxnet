#pragma once

#include <cstddef>

namespace chx::net::detail {
struct monostate_container {
    constexpr void* data() const noexcept(true) { return nullptr; }
    constexpr std::size_t size() const noexcept(true) { return 0; }
};
}  // namespace chx::net::detail
