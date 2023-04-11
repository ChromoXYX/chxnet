#pragma once

#include "./async_token.hpp"
#include "./detail/type_identity.hpp"
#include "attribute.hpp"

namespace chx::net {
namespace detail {
template <typename CompletionToken, typename Value>
struct as_tuple_impl : CompletionToken {
    template <typename T>
    constexpr as_tuple_impl(T&& t, detail::type_identity<Value>) noexcept(
        std::is_nothrow_constructible_v<CompletionToken, decltype(t)>)
        : CompletionToken(std::forward<T>(t)) {}

    template <typename FinalFunctor>
    constexpr decltype(auto) generate_token(io_context::task_t* task,
                                            FinalFunctor&& final_functor) {
        return [final_functor = std::forward<FinalFunctor>(final_functor),
                completion_token =
                    std::move(*this)](io_context::task_t* self) mutable {
            return final_functor(completion_token, self);
        };
    }

    template <typename T> constexpr void get_init(T) noexcept(true) {}

    template <typename... Ts> decltype(auto) operator()(Ts&&... ts) {
        return CompletionToken::operator()(Value(std::forward<Ts>(ts)...));
    }
};
template <typename T, typename V>
as_tuple_impl(T, detail::type_identity<V>)
    -> as_tuple_impl<std::remove_reference_t<T>, V>;

template <typename FinalFunctor, typename CallableObj>
struct as_tuple_impl3 : FinalFunctor, CallableObj {
    template <typename F, typename C>
    as_tuple_impl3(F&& f, C&& c)
        : FinalFunctor(std::forward<F>(f)), CallableObj(std::forward<C>(c)) {}

    decltype(auto) operator()(io_context::task_t* self) {
        return FinalFunctor::operator()(static_cast<CallableObj&>(*this), self);
    }
};
template <typename F, typename C>
as_tuple_impl3(F&&, C&&)
    -> as_tuple_impl3<std::remove_reference_t<F>, std::remove_reference_t<C>>;

template <typename GeneratedToken, typename Value>
struct as_tuple_base_callable : GeneratedToken {
    template <typename G, typename V>
    as_tuple_base_callable(G&& g, detail::type_identity<V>)
        : GeneratedToken(std::forward<G>(g)) {}

    template <typename... Ts> decltype(auto) operator()(Ts&&... ts) {
        return GeneratedToken::operator()(nullptr)(
            Value(std::forward<Ts>(ts)...));
    }
};
template <typename G, typename V>
as_tuple_base_callable(G&&, detail::type_identity<V>)
    -> as_tuple_base_callable<std::remove_reference_t<G>, V>;

template <typename CompletionToken, typename Value> struct as_tuple_impl2 {
    using attribute_type = attribute<async_token>;

    CompletionToken ct;

    template <typename T>
    constexpr as_tuple_impl2(T&& t, detail::type_identity<Value>) noexcept(true)
        : ct(std::forward<T>(t)) {}

    template <typename FinalFunctor>
    constexpr decltype(auto) generate_token(io_context::task_t* task,
                                            FinalFunctor&& final_functor) {
        return as_tuple_impl3(
            std::forward<FinalFunctor>(final_functor),
            as_tuple_base_callable(detail::async_token_generate(
                                       task, __CHXNET_FAKE_FINAL_FUNCTOR(), ct),
                                   detail::type_identity<Value>()));
    }

    template <typename TypeIdentity> decltype(auto) get_init(TypeIdentity ti) {
        return detail::async_token_init(ti, ct);
    }
};
template <typename C, typename V>
as_tuple_impl2(C&& c, detail::type_identity<V>)
    // here CompletionToken must not be reference, since any temp obj generated
    // by bind will destruct after return. but EBO is also useless, since
    // as_tuple_impl2 is only an intermediate.
    ->as_tuple_impl2<std::remove_reference_t<C>, V>;
}  // namespace detail

/**
 * @brief Helper class to combine completion token arguments to a tuple.
 */
template <typename T> struct as_tuple {
    using attribute_type = attribute<async_token>;

    T t;
    static_assert(std::is_reference_v<T>);

    /**
     * @brief Construct a new as_tuple object.
     *
     * @tparam CompletionToken Callable object with signature of a single
     * tuple.
     */
    template <typename CompletionToken>
    constexpr as_tuple(CompletionToken&& completion_token) noexcept(true)
        : t(std::forward<CompletionToken>(completion_token)) {}

    template <typename... Signature> constexpr decltype(auto) bind() {
        if constexpr (is_async_token<std::decay_t<T>>::value) {
            return detail::as_tuple_impl2(
                t.template bind<std::tuple<std::decay_t<Signature>...>>(),
                detail::type_identity<
                    std::tuple<std::decay_t<Signature>...>>());
        } else {
            return detail::as_tuple_impl(
                std::forward<T>(t),
                detail::type_identity<
                    std::tuple<std::decay_t<Signature>...>>());
        }
    }
};
template <typename CompletionToken>
as_tuple(CompletionToken&&) -> as_tuple<CompletionToken&&>;
}  // namespace chx::net
