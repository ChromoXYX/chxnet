#pragma once

#include "../async_write_sequence.hpp"

#include "../detail/sfinae_placeholder.hpp"
#include "../io_context.hpp"
#include "../buffer.hpp"

namespace chx::net::detail {
namespace tags {
struct async_write_seq {};
}  // namespace tags

template <> struct async_operation<tags::async_write_seq> {
    template <typename> struct is_tuple : std::false_type {};
    template <typename... Ts>
    struct is_tuple<std::tuple<Ts...>> : std::true_type {};

    template <typename> struct is_cpp_array : std::false_type {};
    template <typename T, std::size_t Size>
    struct is_cpp_array<std::array<T, Size>> : std::true_type {};

    struct has_begin_end_impl {
        template <typename T, typename = decltype(std::declval<T>().begin()),
                  typename = decltype(std::declval<T>().end())>
        has_begin_end_impl(T&&) {}
    };
    template <typename T>
    using has_begin_end = std::is_constructible<has_begin_end_impl, T>;

    template <typename T>
    using is_atom = std::integral_constant<
        bool, is_buffer<std::decay_t<T>>::value &&
                  (std::is_same_v<std::decay_t<decltype(std::declval<T>()[0])>,
                                  char> ||
                   std::is_same_v<std::decay_t<decltype(std::declval<T>()[0])>,
                                  unsigned char>)>;

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
                 std::enable_if_t<is_cpp_array<std::decay_t<T>>::value ||
                                  std::is_array_v<std::remove_reference_t<T>>>>
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
                                  !(is_cpp_array<std::decay_t<T>>::value ||
                                    std::is_array_v<std::remove_reference_t<
                                        T>>)&&!(is_atom<T&&>::value)>>
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
            std::enable_if_t<is_cpp_array<std::decay_t<T>>::value ||
                             std::is_array_v<std::remove_reference_t<T>>>>
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
                                      (iov_constexpr_size<std::tuple_element_t<
                                           Idx, std::remove_reference_t<Tp>>>()
                                           .value +
                                       ...)>();
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
        return 1;
    }

    template <typename T>
    constexpr static std::size_t iov_static_size(
        T&& t,
        sfinae_placeholder<
            std::enable_if_t<is_cpp_array<std::decay_t<T>>::value ||
                             std::is_array_v<std::remove_reference_t<T>>>>
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
    static std::size_t iov_static_size(
        T&& t,
        sfinae_placeholder<
            std::enable_if_t<has_begin_end<T&&>::value>,
            std::enable_if_t<!(is_cpp_array<std::decay_t<T>>::value ||
                               std::is_array_v<std::remove_reference_t<T>>)>,
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
        v->iov_base = buffer.data();
        v->iov_len = buffer.size();
        ++v;
    }

    template <typename T>
    constexpr static void
    arr_fill(T&& t, iovec*& v,
             sfinae_placeholder<
                 std::enable_if_t<is_cpp_array<std::decay_t<T>>::value ||
                                  std::is_array_v<std::remove_reference_t<T>>>>
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
    static void arr_fill(
        T&& t, iovec*& v,
        sfinae_placeholder<
            std::enable_if_t<has_begin_end<T&&>::value>,
            std::enable_if_t<!(is_cpp_array<std::decay_t<T>>::value ||
                               std::is_array_v<std::remove_reference_t<T>>)>,
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

    template <typename FlatSequence, typename GeneratedCompletionToken>
    struct write_seq2 : GeneratedCompletionToken {
        FlatSequence flat_sequence;
        template <typename FS, typename GCT>
        write_seq2(FS&& fs, GCT&& gct)
            : flat_sequence(std::forward<FS>(fs)),
              GeneratedCompletionToken(std::forward<GCT>(gct)) {}
    };
    template <typename FlatSequence, typename GeneratedCompletionToken>
    write_seq2(FlatSequence&&, GeneratedCompletionToken&&)
        -> write_seq2<std::remove_reference_t<FlatSequence>,
                      std::remove_reference_t<GeneratedCompletionToken>>;

    template <typename SequenceRef, typename BindCompletionToken>
    struct write_seq1 {
        BindCompletionToken bind_completion_token;
        SequenceRef sequence_ref;
        io_context::task_t* task;
        int fd;

        using attribute_type = attribute<async_token>;

        template <typename BCT, typename SR>
        write_seq1(BCT&& bct, SR&& sr, int f)
            : bind_completion_token(std::forward<BCT>(bct)),
              sequence_ref(std::forward<SR>(sr)), fd(f) {}

        template <typename FinalFunctor>
        decltype(auto) generate_token(io_context::task_t* t,
                                      FinalFunctor&& final_functor) {
            task = t;
            return write_seq2(
                fill_iov(std::forward<SequenceRef>(sequence_ref)),
                async_token_generate(
                    t, std::forward<FinalFunctor>(final_functor),
                    std::forward<BindCompletionToken>(bind_completion_token)));
        }

        template <typename TypeIdentity>
        decltype(auto) get_init(TypeIdentity ti) {
            auto* sqe = task->get_associated_io_context().get_sqe(task);
            auto* d = static_cast<typename TypeIdentity::type*>(
                task->get_underlying_data());
            io_uring_prep_writev(sqe, fd, d->flat_sequence.data(),
                                 d->flat_sequence.size(), 0);
            return async_token_init(
                ti, std::forward<BindCompletionToken>(bind_completion_token));
        }
    };
    template <typename SequenceRef, typename BindCompletionToken>
    write_seq1(BindCompletionToken&&, SequenceRef&&, int)
        -> write_seq1<SequenceRef&&, BindCompletionToken&&>;

    template <typename CompletionToken>
    decltype(auto) operator()(io_context* ctx,
                              CompletionToken&& completion_token) {
        auto* task = ctx->acquire();
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) mutable -> int {
                    token(self->__M_ec,
                          static_cast<std::size_t>(self->__M_res));
                    return 0;
                },
                completion_token)),
            completion_token);
    }
};
}  // namespace chx::net::detail

template <typename Stream, typename Sequence, typename CompletionToken>
decltype(auto)
chx::net::async_write_sequence(Stream& stream, Sequence&& sequence,
                               CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::async_write_seq>()(
        &stream.get_associated_io_context(),
        detail::async_operation<detail::tags::async_write_seq>::write_seq1(
            detail::async_token_bind<const std::error_code&, std::size_t>(
                std::forward<CompletionToken>(completion_token)),
            std::forward<Sequence>(sequence), stream.native_handler()));
}
