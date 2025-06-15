#pragma once

#include "../detail/is_container.hpp"

namespace chx::net {
template <typename T> using is_container = detail::is_container<T>;
}  // namespace chx::net
