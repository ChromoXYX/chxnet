#pragma once

#include <cassert>
#include <coroutine>
#include <tuple>
#include <variant>
#include "./detail/remove_rvalue_reference.hpp"

namespace chx::net {
template <typename... Awaitables> struct when_any {
    std::tuple<Awaitables...> a;

    using result_type = std::variant<std::variant<
        typename std::remove_reference_t<Awaitables>::value_type>...>;

    template <typename... As>
    when_any(std::coroutine_handle<> h, As&&... as)
        : a(std::forward<As>(as)...) {
        std::apply([&](auto&&... as) { (..., as.set_parent(h)); }, a);
    }

    template <std::size_t I> result_type get_return_value() {
        if constexpr (I != sizeof...(Awaitables)) {
            auto awa = std::get<I>(a).operator co_await();
            if (awa.await_ready()) {
                return result_type(std::in_place_index<I>, awa.await_resume());
            } else {
                return get_return_value<I + 1>();
            }
        } else {
            assert(false);
        }
    }

    auto operator co_await() {
        struct awaitable : std::suspend_always {
            when_any& self;

            bool await_ready() noexcept(true) {
                return std::apply(
                    [](auto&&... as) {
                        return (... || as.operator co_await().await_ready());
                    },
                    self.a);
            }
            result_type await_resume() { return self.get_return_value<0>(); }
        };
        return awaitable{{}, *this};
    }
};
template <typename... Awaitables>
when_any(std::coroutine_handle<>, Awaitables&&... as) -> when_any<
    typename detail::remove_rvalue_reference<Awaitables&&>::type...>;
}  // namespace chx::net
