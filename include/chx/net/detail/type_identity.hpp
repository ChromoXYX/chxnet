#pragma once

namespace chx::net::detail {
template <typename T> struct type_identity {
    using type = T;
};
}  // namespace chx::net::detail
