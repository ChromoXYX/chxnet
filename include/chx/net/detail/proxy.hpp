#pragma once

#include "../task_decl.hpp"
#include "../async_token.hpp"
#include <utility>
#include <type_traits>

namespace chx::net::detail {
template <typename GeneratedCallable, typename Proxy>
struct proxy_callable : GeneratedCallable, private Proxy {
    proxy_callable(GeneratedCallable&& gc, Proxy&& p)
        : GeneratedCallable(std::move(gc)), Proxy(std::move(p)) {}

    template <typename... Ts> decltype(auto) operator()(Ts&&... ts) {
        return Proxy::operator()(static_cast<GeneratedCallable&>(*this),
                                 std::forward<Ts>(ts)...);
    }
};

template <typename ProxyCallable, typename FinalFunctor>
struct proxy_gct : ProxyCallable, private FinalFunctor {
    template <typename PC, typename FF>
    proxy_gct(PC&& pc, FF&& ff)
        : ProxyCallable(std::forward<PC>(pc)),
          FinalFunctor(std::forward<FF>(ff)) {}

    decltype(auto) operator()(task_decl* self) {
        return FinalFunctor::operator()(static_cast<ProxyCallable&>(*this),
                                        self);
    }
};

template <typename ProxyCallable, typename FinalFunctor>
proxy_gct(ProxyCallable&&, FinalFunctor&&)
    -> proxy_gct<std::remove_reference_t<ProxyCallable>,
                 std::remove_reference_t<FinalFunctor>>;

template <typename BindCompletionToken, typename Proxy> struct proxy_bct {
    using attribute_type = attribute<async_token>;

    BindCompletionToken bind_completion_token;
    Proxy proxy;

    template <typename BCT, typename P>
    proxy_bct(BCT&& bct, P&& p)
        : bind_completion_token(std::forward<BCT>(bct)),
          proxy(std::forward<P>(p)) {}

    template <typename FinalFunctor>
    decltype(auto) generate_token(task_decl* task,
                                  FinalFunctor&& final_functor) {
        return proxy_gct(
            proxy_callable(
                std::move(async_token_generate(
                    task,
                    [](auto& token, task_decl*) -> auto& { return token; },
                    bind_completion_token)(nullptr)),
                std::move(proxy)),
            std::forward<FinalFunctor>(final_functor));
    }

    template <typename TypeIdentity> decltype(auto) get_init(TypeIdentity ti) {
        return detail::async_token_init(ti, bind_completion_token);
    }
};

template <typename BindCompletionToken, typename Proxy>
proxy_bct(BindCompletionToken&&, Proxy&&)
    -> proxy_bct<std::remove_reference_t<BindCompletionToken>,
                 std::remove_reference_t<Proxy>>;

template <typename Proxy, typename CompletionToken, typename... Sig>
struct proxy_impl {
    using attribute_type = attribute<async_token>;

    Proxy proxy;
    CompletionToken completion_token;

    template <typename P, typename CT>
    proxy_impl(P&& p, CT&& ct, type_identity<std::tuple<Sig...>>)
        : proxy(std::forward<P>(p)), completion_token(std::forward<CT>(ct)) {}

    template <typename... _Sig> decltype(auto) bind() {
        return proxy_bct(async_token_bind<Sig...>(std::move(completion_token)),
                         std::move(proxy));
    }
};

template <typename Proxy, typename CompletionToken, typename... Sig>
proxy_impl(Proxy&&, CompletionToken&&, type_identity<std::tuple<Sig...>>)
    -> proxy_impl<std::remove_reference_t<Proxy>,
                  std::remove_reference_t<CompletionToken>, Sig...>;

template <typename... Sig, typename Proxy, typename CompletionToken>
decltype(auto) proxy(Proxy&& proxy, CompletionToken&& completion_token) {
    return proxy_impl(std::forward<Proxy>(proxy),
                      std::forward<CompletionToken>(completion_token),
                      type_identity<std::tuple<Sig...>>{});
}
}  // namespace chx::net::detail
