#pragma once

#include <sys/socket.h>
#include "../detail/is_container.hpp"

namespace chx::net {
namespace detail {
template <typename T> constexpr auto is_sequence_impl() {
    if constexpr (is_container<T>::value) {
        return std::is_convertible<decltype(std::declval<T>().data()),
                                   const struct iovec*>{};
    } else {
        return std::false_type{};
    }
}
}  // namespace detail

template <typename T>
using is_sequence = decltype(detail::is_sequence_impl<T>());
}  // namespace chx::net
