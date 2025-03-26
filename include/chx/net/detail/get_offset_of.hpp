#pragma once

#include <cstddef>
#include <utility>

namespace chx::net::detail {
template <typename Ptr> struct pointer_to_member;
template <typename M, typename T> struct pointer_to_member<M T::*> {
    using member_type = M;
    using type = T;
};

template <typename M, typename T> union get_offset_of_impl {
    char c = 0;
    M m;
    T t;
};
template <typename M, typename T>
extern get_offset_of_impl<M, T> you_should_never_use_this_name;

template <auto Ptr> struct get_offset_of {
    using traits = pointer_to_member<decltype(Ptr)>;
    union C {
        char c = 0;
        typename traits::member_type m;
        typename traits::type t;
    };

    constexpr static std::size_t f() {
        return (std::addressof(you_should_never_use_this_name<typename traits::member_type,typename traits::type>.t.*Ptr) -
                std::addressof((you_should_never_use_this_name<typename traits::member_type,typename traits::type>.m))) *
               sizeof(typename traits::member_type);
    }

    constexpr static inline std::size_t value = f();
};
}  // namespace chx::net::detail
