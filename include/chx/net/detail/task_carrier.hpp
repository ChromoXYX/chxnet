#pragma once

#include "./type_identity.hpp"
#include "../async_token.hpp"
#include <utility>

namespace chx::net::detail {
template <typename GeneratedCompletionToken, typename Data>
struct task_carrier_s3 : GeneratedCompletionToken {
    Data data;

    template <typename GCT, typename D>
    constexpr task_carrier_s3(GCT&& gct, D&& d)
        : GeneratedCompletionToken(std::forward<GCT>(gct)),
          data(std::forward<D>(d)) {}
};
template <typename GeneratedCompletionToken, typename Data>
task_carrier_s3(GeneratedCompletionToken&&, Data&&)
    -> task_carrier_s3<std::remove_reference_t<GeneratedCompletionToken>,
                       std::remove_reference_t<Data>>;

template <typename BindCompletionToken, typename Data, typename Callback>
struct task_carrier_s2 {
    using attribute_type = attribute<async_token>;

    BindCompletionToken bind_completion_token;
    Data data;
    task_decl* task = nullptr;

    Callback callback;

    template <typename BCT, typename D, typename C>
    constexpr task_carrier_s2(BCT&& bct, D&& d, C&& c)
        : bind_completion_token(std::forward<BCT>(bct)),
          data(std::forward<D>(d)), callback(std::forward<C>(c)) {}

    template <typename GCT>
    constexpr task_carrier_s3<GCT, Data>*
    get_s3(task_carrier_s3<GCT, Data>* ptr) noexcept(true) {
        return ptr;
    }

    template <typename FinalFunctor>
    constexpr decltype(auto) generate_token(task_decl* t,
                                            FinalFunctor&& final_functor) {
        task = t;
        return task_carrier_s3(
            async_token_generate(task,
                                 std::forward<FinalFunctor>(final_functor),
                                 bind_completion_token),
            std::move(data));
    }
    template <typename TI> constexpr decltype(auto) get_init(TI ti) {
        callback(task, ti,
                 type_identity<typename std::pointer_traits<decltype(get_s3(
                     static_cast<typename TI::type*>(
                         task->get_underlying_data())))>::element_type>{});
        return async_token_init(ti, bind_completion_token);
    }
};
template <typename BindCompletionToken, typename Data, typename Callback>
task_carrier_s2(BindCompletionToken&&, Data&&, Callback&&)
    -> task_carrier_s2<std::remove_reference_t<BindCompletionToken>,
                       std::remove_reference_t<Data>,
                       std::remove_reference_t<Callback>>;

template <typename CompletionToken, typename Data, typename Callback>
struct task_carrier_s1 {
    using attribute_type = attribute<async_token>;

    CompletionToken completion_token;
    Data data;
    Callback callback;

    template <typename CT, typename D, typename C>
    constexpr task_carrier_s1(CT&& ct, D&& d, C&& c)
        : completion_token(std::forward<CT>(ct)), data(std::forward<D>(d)),
          callback(std::forward<C>(c)) {}

    template <typename... Sig> constexpr decltype(auto) bind() {
        return task_carrier_s2(async_token_bind<Sig...>(completion_token),
                               std::move(data), std::move(callback));
    }
};
template <typename BindCompletionToken, typename Data, typename Callback>
task_carrier_s1(BindCompletionToken&&, Data&&, Callback&&)
    -> task_carrier_s1<std::remove_reference_t<BindCompletionToken>,
                       std::remove_reference_t<Data>,
                       std::remove_reference_t<Callback>>;
}  // namespace chx::net::detail
