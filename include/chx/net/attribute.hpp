#pragma once

#include <tuple>
#include <type_traits>

namespace chx::net {
template <typename... Attributes> struct attribute {};

namespace detail {
template <typename T> struct has_attribute_impl {
    template <typename R> static std::true_type f(typename R::attribute_type*);
    template <typename R> static std::false_type f(...);

    using type = decltype(has_attribute_impl::f<T>(0));
};
template <typename T> struct has_attribute : has_attribute_impl<T>::type {};

template <typename Target> constexpr bool check_attr_impl() noexcept(true) {
    return false;
}
template <typename Target, typename T, typename... Ts>
constexpr bool check_attr_impl() noexcept(true) {
    if constexpr (std::is_same_v<Target, T>) {
        return true;
    } else {
        return check_attr_impl<Target, Ts...>();
    }
}

template <typename Target, typename T> struct check_attr_impl2 {};
template <typename Target, typename... Attributes>
struct check_attr_impl2<Target, attribute<Attributes...>>
    : std::integral_constant<bool, check_attr_impl<Target, Attributes...>()> {};

template <typename Tp> struct tp_to_attr;
template <typename... Attr> struct tp_to_attr<std::tuple<Attr...>> {
    using type = attribute<Attr...>;
};

template <typename Target, typename... Origin> struct remove_attr {
    using type = typename tp_to_attr<decltype(std::tuple_cat(
        std::conditional_t<std::is_same_v<Target, Origin>, std::tuple<>,
                           std::tuple<Origin>>()...))>::type;
};
template <typename Target, typename T> struct remove_attr_wrapper;
template <typename Target, typename... Attrs>
struct remove_attr_wrapper<Target, attribute<Attrs...>> {
    using type = typename remove_attr<Target, Attrs...>::type;
};
}  // namespace detail

template <typename Target, typename T>
constexpr bool check_attr() noexcept(true) {
    if constexpr (detail::has_attribute<T>::value) {
        return detail::check_attr_impl2<Target,
                                        typename T::attribute_type>::value;
    } else {
        return false;
    }
}
template <typename Target, typename T>
using check_attr_type = std::integral_constant<bool, check_attr<Target, T>()>;
template <typename Target, typename T>
using remove_attr =
    typename detail::remove_attr_wrapper<Target,
                                         typename T::attribute_type>::type;
}  // namespace chx::net
