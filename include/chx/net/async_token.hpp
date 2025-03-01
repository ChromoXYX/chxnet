#pragma once

#include "./attribute.hpp"
#include "./task_decl.hpp"

#include <cassert>

namespace chx::net {
/**
 * @brief Base type of AsyncToken.
 *
 */
struct async_token {};

/**
 * @brief Helper class to determine whether the type is an AsyncToken.
 *
 * @tparam T
 */
template <typename T> using is_async_token = check_attr_type<async_token, T>;

namespace detail {
template <typename... Signature, typename CompletionToken>
constexpr decltype(auto)
async_token_bind(CompletionToken&& token) noexcept(true) {
    if constexpr (is_async_token<std::decay_t<CompletionToken>>::value) {
        return token.template bind<Signature...>();
    } else {
        return std::forward<CompletionToken>(token);
    }
}

template <typename FinalFunctor, typename CompletionToken>
constexpr decltype(auto)
async_token_generate(task_decl* task, FinalFunctor&& final_functor,
                     CompletionToken&& token) noexcept(true) {
    assert(task);
    if constexpr (is_async_token<std::decay_t<CompletionToken>>::value) {
        return token.generate_token(task,
                                    std::forward<FinalFunctor>(final_functor));
    } else {
        // what if final_functor is fake_final_functor? here, completion_token
        // will be move into lambda, so there is no need to worry about the
        // lifetime for the completion_token.
        return
            [final_functor = std::move(final_functor),
             token = std::move(token)](task_decl* t) mutable -> decltype(auto) {
                return final_functor(token, t);
            };
    }
}

template <typename TypeIdentity, typename CompletionToken>
constexpr decltype(auto)
async_token_init(TypeIdentity, CompletionToken&& token) noexcept(true) {
    if constexpr (is_async_token<std::decay_t<CompletionToken>>::value) {
        return token.get_init(TypeIdentity());
    } else {
        return;
    }
};

struct fake_final_functor {
    // ONLY return LVALUE reference
    template <typename GeneratedToken>
    constexpr GeneratedToken& operator()(GeneratedToken& generated_token,
                                         task_decl*) noexcept(true) {
        return generated_token;
    }
};
}  // namespace detail
}  // namespace chx::net
