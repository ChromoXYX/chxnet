#pragma once

#include "../async_token.hpp"

namespace chx::net::detail {
template <typename BindCompletionToken> struct task_aware_ops {
    using attribute_type = attribute<async_token>;

    BindCompletionToken bind_completion_token;

    template <typename BCT>
    constexpr task_aware_ops(BCT&& bct) noexcept(true)
        : bind_completion_token(std::forward<BCT>(bct)) {}

    template <typename FinalFunctor>
    decltype(auto) generate_token(io_context::task_t* task,
                                  FinalFunctor&& final_functor) {
        bind_completion_token.aware(task);
        return async_token_generate(task,
                                    std::forward<FinalFunctor>(final_functor),
                                    bind_completion_token);
    }

    template <typename T> decltype(auto) get_init(T&& t) {
        return async_token_init(t, bind_completion_token);
    }
};
template <typename BindCompletionToken>
task_aware_ops(BindCompletionToken&&)
    -> task_aware_ops<std::remove_reference_t<BindCompletionToken>>;

template <typename CompletionToken> struct task_aware {
    using attribute_type = attribute<async_token>;

    CompletionToken completion_token;

    template <typename CT>
    constexpr task_aware(CT&& r) noexcept(true)
        : completion_token(std::forward<CT>(r)) {}

    template <typename... S> decltype(auto) bind() {
        return task_aware_ops(std::move(completion_token));
    }
};
template <typename CompletionToken>
task_aware(CompletionToken&&)
    -> task_aware<std::remove_reference_t<CompletionToken>>;
}  // namespace chx::net::detail
