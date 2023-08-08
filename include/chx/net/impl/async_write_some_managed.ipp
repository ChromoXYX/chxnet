#pragma once

#include "../managed.hpp"

#include "../io_context.hpp"
#include "../async_combine.hpp"
#include "../buffer_sequence.hpp"

namespace chx::net::detail::tags {
struct write_managed {};
struct writev_managed {};
}  // namespace chx::net::detail::tags

namespace chx::net::detail {
struct clearable_impl {
    template <typename T, typename = decltype(std::declval<T>().clear())>
    clearable_impl(T&&) {}
};
template <typename T>
using container_clearable = std::is_constructible<clearable_impl, T>;
}  // namespace chx::net::detail

template <>
struct chx::net::detail::async_operation<
    chx::net::detail::tags::write_managed> {
    template <typename CompletionToken>
    static void nop(io_context* ctx, CompletionToken&& completion_token) {
        auto [sqe, task] = ctx->get();
        sqe->flags |= IOSQE_IO_LINK;
        io_uring_prep_nop(sqe);
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) mutable -> int {
                    token(self->__M_ec);
                    return 0;
                },
                completion_token)),
            completion_token);
    }

    template <typename Stream, typename Container, typename CntlType = void>
    struct operation {
        Stream stream;
        Container container;

        template <typename T> using rebind = operation<Stream, Container, T>;

        template <typename Cntl> void operator()(Cntl& cntl) {
            static_assert(!std::is_same_v<CntlType, void>);
            io_context& ctx = stream.get_associated_io_context();
            nop(&ctx, async_token_bind<const std::error_code&>(cntl.next()));
            unsigned int low_boundary = ctx.__M_ring.sq.sqe_head;
            stream.async_write_some(buffer(container), cntl.next());
            if (low_boundary != ctx.__M_ring.sq.sqe_head) {
                ctx.submit();
            }
        }

        template <typename S, typename C>
        operation(S&& s, C&& c)
            : stream(std::forward<S>(s)), container(std::forward<C>(c)) {}

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code&) {
            if constexpr (container_clearable<Container>::value) {
                container.clear();
            }
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e, std::size_t s) {
            cntl.complete(e, s);
        }
    };
    template <typename Stream, typename Container>
    operation(Stream&, Container&&)
        -> operation<Stream&, std::decay_t<Container>>;
    template <typename Stream, typename Container>
    operation(Stream&&, Container&&)
        -> operation<Stream, std::decay_t<Container>>;
};

template <>
struct chx::net::detail::async_operation<
    chx::net::detail::tags::writev_managed> {
    template <typename Container>
    static auto generate_iovec(Container& container) {
        using type =
            is_const_buffer_sequence<std::remove_reference_t<Container>>;
        if constexpr (type::has_static_size == true) {
            return generate_iovec_array_const(
                container,
                std::make_integer_sequence<std::size_t, type::static_size>());
        } else {
            std::vector<struct iovec> iovec_vec(
                std::distance(container.begin(), container.end()));
            auto iterator = iovec_vec.begin();
            for (auto& i : container) {
                *(iterator++) = to_iovec_const(const_buffer(i));
            }
            return std::move(iovec_vec);
        }
    }

    template <typename Iov, typename CompletionToken>
    static decltype(auto)
    async_writev_impl(io_context* ctx, int fd, Iov& iov,
                      CompletionToken&& completion_token) {
        auto [sqe, task] = ctx->get();
        io_uring_prep_writev(sqe, fd, iov.data(), iov.size(), 0);
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

    template <typename Stream, typename Container, typename CntlType = void>
    struct operation {
        Stream stream;
        Container container;
        decltype(generate_iovec(container)) iov;

        template <typename T> using rebind = operation<Stream, Container, T>;

        template <typename S, typename C>
        operation(S&& s, C&& c)
            : stream(std::forward<S>(s)), container(std::forward<C>(c)),
              iov(generate_iovec(container)) {}

        template <typename Cntl> void operator()(Cntl& cntl) {
            static_assert(!std::is_same_v<CntlType, void>);
            io_context& ctx = stream.get_associated_io_context();
            async_operation<tags::write_managed>::nop(
                &ctx, async_token_bind<const std::error_code&>(cntl.next()));
            unsigned int low_boundary = ctx.__M_ring.sq.sqe_head;
            async_writev_impl(
                &ctx, stream.native_handler(), iov,
                async_token_bind<const std::error_code&, std::size_t>(
                    cntl.next()));
            if (low_boundary != ctx.__M_ring.sq.sqe_head) {
                ctx.submit();
            }
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code&) {
            if constexpr (!is_const_buffer_sequence<
                              Container>::has_static_size) {
                iov.clear();
            }
            using value_type =
                std::remove_reference_t<decltype(*std::begin(container))>;
            if constexpr (container_clearable<Container>::value) {
                container.clear();
            } else if constexpr (container_clearable<value_type>::value) {
                for (auto& i : container) {
                    i.clear();
                }
            }
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e, std::size_t s) {
            cntl.complete(e, s);
        }
    };
    template <typename Stream, typename Container>
    operation(Stream&, Container&&)
        -> operation<Stream&, std::decay_t<Container>>;
    template <typename Stream, typename Container>
    operation(Stream&&, Container&&)
        -> operation<Stream, std::decay_t<Container>>;
};

template <typename Stream, typename Container, typename CompletionToken>
decltype(auto)
chx::net::async_write_some_managed(Stream&& stream, Container&& container,
                                   CompletionToken&& completion_token) {
    if constexpr (!is_const_buffer_sequence<std::decay_t<Container>>::value) {
        using operation_type =
            decltype(detail::async_operation<detail::tags::write_managed>::
                         operation(std::forward<Stream>(stream),
                                   std::forward<Container>(container)));
        return async_combine<const std::error_code&, std::size_t>(
            stream.get_associated_io_context(),
            std::forward<CompletionToken>(completion_token),
            detail::type_identity<operation_type>(),
            std::forward<Stream>(stream), std::forward<Container>(container));
    } else {
        using operation_type =
            decltype(detail::async_operation<detail::tags::writev_managed>::
                         operation(std::forward<Stream>(stream),
                                   std::forward<Container>(container)));
        return async_combine<const std::error_code&, std::size_t>(
            stream.get_associated_io_context(),
            std::forward<CompletionToken>(completion_token),
            detail::type_identity<operation_type>(),
            std::forward<Stream>(stream), std::forward<Container>(container));
    }
}
