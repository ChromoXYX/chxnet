#pragma once

#include <cstddef>
#include <numeric>
#include <optional>
#include <tuple>
#include <variant>
#include "./is_container.hpp"

namespace chx::net::detail {
template <typename T> struct is_tuple : std::false_type {};
template <typename... Ts>
struct is_tuple<std::tuple<Ts...>> : std::true_type {};
template <typename T> struct is_variant : std::false_type {};
template <typename... Ts>
struct is_variant<std::variant<Ts...>> : std::true_type {};
template <typename T> struct is_optional : std::false_type {};
template <typename T> struct is_optional<std::optional<T>> : std::true_type {};

template <typename T> constexpr std::size_t accumulate_size(T&& t) {
    if constexpr (is_container<T>::value) {
        using value_type =
            std::decay_t<std::remove_pointer_t<decltype(t.data())>>;
        if constexpr (std::is_same_v<value_type, unsigned char> ||
                      std::is_same_v<value_type, char> ||
                      std::is_same_v<value_type, void> ||
                      !has_begin_end<T>::value) {
            return t.size();
        } else {
            return std::accumulate(t.begin(), t.end(), std::size_t{},
                                   [](std::size_t s, const auto& v) {
                                       return s + accumulate_size(v);
                                   });
        }
    } else if constexpr (is_tuple<std::decay_t<T>>::value) {
        return std::apply(
            [](auto&&... ts) { return (0 + ... + accumulate_size(ts)); }, t);
    } else if constexpr (is_variant<std::decay_t<T>>::value) {
        return std::visit(
            [](const auto& item) { return accumulate_size(item); }, t);
    } else if constexpr (is_optional<std::decay_t<T>>::value) {
        return t ? accumulate_size(*t) : 0;
    } else {
        static_assert(false);
    }
}
}  // namespace chx::net::detail