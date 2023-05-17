#pragma once

#include "../file_descriptor.hpp"

namespace chx::net::detail {
namespace tags {
struct fd_read {};
struct fd_write {};
}  // namespace tags

template <> struct async_operation<tags::fd_read> {
    template <typename CompletionToken>
    decltype(auto) operator()(file_descriptor* fd,
                              const mutable_buffer& mutable_buffer,
                              CompletionToken&& completion_token) {
        auto [sqe, task] = fd->get_associated_io_context().get();

        io_uring_prep_read(sqe, fd->native_handler(), mutable_buffer.data(),
                           mutable_buffer.size(), 0);
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) mutable -> int {
                    token(self->__M_ec, self->__M_res);
                    return 0;
                },
                completion_token)),
            completion_token);
    }
};
template <> struct async_operation<tags::fd_write> {
    template <typename CompletionToken>
    decltype(auto) operator()(file_descriptor* fd,
                              const const_buffer& const_buffer,
                              CompletionToken&& completion_token) {
        auto [sqe, task] = fd->get_associated_io_context().get();

        io_uring_prep_write(sqe, fd->native_handler(), const_buffer.data(),
                            const_buffer.size(), 0);
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) mutable -> int {
                    token(self->__M_ec, self->__M_res);
                    return 0;
                },
                completion_token)),
            completion_token);
    }
};
}  // namespace chx::net::detail

template <typename MutableBuffer, typename CompletionToken>
decltype(auto) chx::net::file_descriptor::async_read_some(
    MutableBuffer&& mutable_buffer, CompletionToken&& completion_token,
    detail::sfinae_placeholder<
        std::enable_if_t<detail::is_mutable_buffer<MutableBuffer>::value>>) {
    return detail::async_operation<detail::tags::fd_read>()(
        this, mutable_buffer,
        detail::async_token_bind<const std::error_code&, std::size_t>(
            std::forward<CompletionToken>(completion_token)));
}

template <typename ConstBuffer, typename CompletionToken>
decltype(auto) chx::net::file_descriptor::async_write_some(
    ConstBuffer&& const_buffer, CompletionToken&& completion_token,
    detail::sfinae_placeholder<
        std::enable_if_t<detail::is_const_buffer<ConstBuffer>::value>>) {
    return detail::async_operation<detail::tags::fd_write>()(
        this, const_buffer,
        detail::async_token_bind<const std::error_code&, std::size_t>(
            std::forward<CompletionToken>(completion_token)));
}
