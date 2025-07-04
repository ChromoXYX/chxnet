#pragma once

#include <tuple>
#include <variant>
#include <vector>

#include "./sfinae_placeholder.hpp"
#include "../iovec_buffer.hpp"

namespace chx::net {
namespace detail {
struct flatten_sequence_impl {
    template <typename> struct is_tuple : std::false_type {};
    template <typename... Ts>
    struct is_tuple<std::tuple<Ts...>> : std::true_type {};

    template <typename> struct is_cpp_array : std::false_type {};
    template <typename T, std::size_t Size>
    struct is_cpp_array<std::array<T, Size>> : std::true_type {};

    template <typename> struct is_variant : std::false_type {};
    template <typename... Ts>
    struct is_variant<std::variant<Ts...>> : std::true_type {};

    template <typename T> struct is_iovec_vector : std::false_type {};
    template <typename Allocator>
    struct is_iovec_vector<std::vector<iovec_buffer, Allocator>>
        : std::true_type {};

    template <typename T> constexpr static auto value_type_check_impl() {
        using rc_t = std::remove_const_t<T>;
        if constexpr (std::is_same_v<rc_t, unsigned char> ||
                      std::is_same_v<rc_t, char> ||
                      std::is_same_v<rc_t, void>) {
            return std::true_type{};
        } else {
            return std::false_type{};
        }
    }
    template <typename T>
    using value_type_check = decltype(value_type_check_impl<T>());

    template <typename T>
    constexpr static auto is_cpp_array_2_impl() noexcept(true) {
        if constexpr (is_cpp_array<T>::value) {
            using element_type = typename T::value_type;
            if constexpr (value_type_check<element_type>::value) {
                return std::false_type{};
            } else {
                return std::true_type{};
            }
        } else {
            return std::false_type{};
        }
    }
    template <typename T>
    using is_cpp_array_2 = decltype(is_cpp_array_2_impl<T>());

    struct has_begin_end_impl {
        template <typename T, typename = decltype(std::declval<T>().begin()),
                  typename = decltype(std::declval<T>().end())>
        has_begin_end_impl(T&&) {}
    };
    template <typename T>
    using has_begin_end = std::is_constructible<has_begin_end_impl, T>;

    template <typename T> constexpr static auto is_atom2() noexcept(true) {
        // if constexpr (std::is_array_v<std::remove_reference_t<T>>) {
        //     using vt = std::decay_t<decltype(std::declval<T>()[0])>;
        //     return std::integral_constant<bool,
        //     value_type_check<vt>::value>{};
        // } else {
        if constexpr (is_buffer<std::decay_t<T>>::value) {
            return value_type_check<typename std::pointer_traits<
                decltype(std::data(std::declval<T>()))>::element_type>();
        } else {
            return std::false_type{};
        }
        // }
    }
    template <typename T> using is_atom = decltype(is_atom2<T>());

    template <typename T>
    constexpr static auto traverse(
        T&& t,
        sfinae_placeholder<std::enable_if_t<is_atom<T&&>::value>> _ = sfinae) {
        return std::true_type{};
    }

    template <typename T>
    constexpr static auto
    traverse(T&& t,
             sfinae_placeholder<
                 std::enable_if_t<is_cpp_array_2<std::decay_t<T>>::value>>
                 _ = sfinae) {
        return traverse(std::forward<T>(t)[0]);
    }

    template <typename T>
    constexpr static auto traverse(
        T&& t,
        sfinae_placeholder<std::enable_if_t<is_tuple<std::decay_t<T>>::value>>
            _ = sfinae) {
        return std::apply(
            [](auto&&... ts) {
                return std::integral_constant<
                    bool, (... && decltype(traverse(std::forward<decltype(ts)>(
                                      ts)))::value)>{};
            },
            std::forward<T>(t));
    }

    template <typename T>
    constexpr static auto
    traverse(T&& t,
             sfinae_placeholder<
                 std::enable_if_t<!(is_tuple<std::decay_t<T>>::value) &&
                                  !(is_cpp_array_2<std::decay_t<T>>::value) &&
                                  !(is_atom<T&&>::value)>>
                 _ = sfinae) {
        return std::false_type{};
    }

    template <typename> struct arr_N;
    template <typename T, std::size_t N>
    struct arr_N<T[N]> : std::integral_constant<std::size_t, N> {};
    template <typename T, std::size_t N>
    struct arr_N<std::array<T, N>> : std::integral_constant<std::size_t, N> {};

    template <typename T>
    constexpr static auto iov_constexpr_size(
        sfinae_placeholder<std::enable_if_t<is_atom<T&&>::value>> _ = sfinae) {
        return std::integral_constant<std::size_t, 1>();
    }
    template <typename T>
    constexpr static auto iov_constexpr_size(
        sfinae_placeholder<
            std::enable_if_t<is_cpp_array_2<std::decay_t<T>>::value>>
            _ = sfinae) {
        return std::integral_constant<
            std::size_t,
            iov_constexpr_size<
                std::remove_reference_t<decltype(std::declval<T>()[0])>>()
                    .value *
                arr_N<std::remove_const_t<std::remove_reference_t<T&&>>>::
                    value>();
    }
    template <typename Tp, std::size_t... Idx>
    constexpr static auto
    traverse_tp_constexpr(std::integer_sequence<std::size_t, Idx...>) {
        return std::integral_constant<std::size_t,
                                      (0 + ... +
                                       iov_constexpr_size<std::tuple_element_t<
                                           Idx, std::remove_reference_t<Tp>>>()
                                           .value)>();
    }
    template <typename T>
    constexpr static auto iov_constexpr_size(
        sfinae_placeholder<std::enable_if_t<is_tuple<std::decay_t<T>>::value>>
            _ = sfinae) {
        return traverse_tp_constexpr<T>(
            std::make_integer_sequence<
                std::size_t, std::tuple_size_v<std::remove_reference_t<T>>>());
    }

    template <typename T>
    constexpr static std::size_t iov_static_size(
        T&& t,
        sfinae_placeholder<std::enable_if_t<is_atom<T&&>::value>> _ = sfinae) {
        return net::buffer(t).size() != 0;
    }

    template <typename T>
    constexpr static std::size_t iov_static_size(
        T&& t, sfinae_placeholder<
                   std::enable_if_t<is_cpp_array_2<std::decay_t<T>>::value>>
                   _ = sfinae) {
        // change array[0:n] to for
        std::size_t r = 0;
        for (auto& i : t) {
            r += iov_static_size(i);
        }
        return r;
    }

    template <typename T>
    constexpr static std::size_t iov_static_size(
        T&& t,
        sfinae_placeholder<std::enable_if_t<is_tuple<std::decay_t<T>>::value>>
            _ = sfinae) {
        return std::apply(
            [](auto&&... ts) {
                return (... + iov_static_size(std::forward<decltype(ts)>(ts)));
            },
            std::forward<T>(t));
    }

    template <typename T>
    constexpr static std::size_t iov_static_size(
        T&& t,
        sfinae_placeholder<std::enable_if_t<is_variant<std::decay_t<T>>::value>>
            _ = sfinae) {
        return !t.valueless_by_exception()
                   ? std::visit(
                         [](auto&& v) {
                             return iov_static_size(
                                 std::forward<decltype(v)>(v));
                         },
                         std::forward<T>(t))
                   : 0;
    }

    template <typename T>
    static std::size_t iov_static_size(
        T&& t, sfinae_placeholder<
                   std::enable_if_t<has_begin_end<T&&>::value>,
                   std::enable_if_t<!(is_cpp_array_2<std::decay_t<T>>::value)>,
                   std::enable_if_t<!is_atom<T&&>::value>>
                   _ = sfinae) {
        std::size_t r = 0;
        for (auto& i : t) {
            r += iov_static_size(i);
        }
        return r;
    }

    template <typename T>
    constexpr static void arr_fill(
        T&& t, iovec*& v,
        sfinae_placeholder<std::enable_if_t<is_atom<T&&>::value>> _ = sfinae) {
        auto buffer = net::buffer(std::forward<T>(t));
        if (buffer.size()) {
            v->iov_base = const_cast<void*>(buffer.data());
            v->iov_len = buffer.size();
            ++v;
        }
    }

    template <typename T>
    constexpr static void
    arr_fill(T&& t, iovec*& v,
             sfinae_placeholder<
                 std::enable_if_t<is_cpp_array_2<std::decay_t<T>>::value>>
                 _ = sfinae) {
        for (auto& i : t) {
            arr_fill(i, v);
        }
    }

    template <typename T>
    constexpr static void arr_fill(
        T&& t, iovec*& v,
        sfinae_placeholder<std::enable_if_t<is_tuple<std::decay_t<T>>::value>>
            _ = sfinae) {
        std::apply(
            [&v](auto&&... ts) {
                (arr_fill(std::forward<decltype(ts)>(ts), v), ...);
            },
            std::forward<T>(t));
    }

    template <typename T>
    constexpr static void arr_fill(
        T&& t, iovec*& v,
        sfinae_placeholder<std::enable_if_t<is_variant<std::decay_t<T>>::value>>
            _ = sfinae) {
        if (!t.valueless_by_exception()) {
            std::visit(
                [&v](auto&& item) {
                    arr_fill(std::forward<decltype(item)>(item), v);
                },
                std::forward<T>(t));
        }
    }

    template <typename T>
    static void
    arr_fill(T&& t, iovec*& v,
             sfinae_placeholder<
                 std::enable_if_t<has_begin_end<T&&>::value>,
                 std::enable_if_t<!(is_cpp_array_2<std::decay_t<T>>::value)>,
                 std::enable_if_t<!is_atom<T&&>::value>>
                 _ = sfinae) {
        for (auto& i : t) {
            arr_fill(i, v);
        }
    }

    template <typename T> static auto fill_iov(T&& t) {
        using cond = decltype(traverse(std::forward<T>(t)));
        if constexpr (cond::value) {
            constexpr std::size_t n = iov_constexpr_size<T>().value;
            std::array<struct iovec, n> a;
            struct iovec* ptr = a.data();
            arr_fill(std::forward<T>(t), ptr);
            return std::move(a);
        } else {
            std::vector<struct iovec> v(iov_static_size(std::forward<T>(t)));
            struct iovec* ptr = v.data();
            arr_fill(std::forward<T>(t), ptr);
            return std::move(v);
        }
    }
};
}  // namespace detail

template <typename Sequence>
using flatten_sequence_type = std::invoke_result_t<
    decltype(detail::flatten_sequence_impl::fill_iov<Sequence&>), Sequence&>;

template <typename Sequence>
constexpr auto flatten_sequence(Sequence& seq)
    -> flatten_sequence_type<Sequence> {
    return detail::flatten_sequence_impl::fill_iov(seq);
}
}  // namespace chx::net
