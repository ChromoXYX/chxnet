#pragma once

#include "../detail/remove_rvalue_reference.hpp"

namespace chx::net {
template <typename T>
using remove_rvalue_reference = detail::remove_rvalue_reference<T>;
}
