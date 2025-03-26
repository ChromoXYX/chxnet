#pragma once

#include "../file.hpp"

namespace chx::net::detail {
namespace tags {
struct file_openat2 {};
}  // namespace tags

template <> struct async_operation<tags::file_openat2> {
    template <typename CompletionToken>
    decltype(auto) operator()(io_context* ctx, file* f, int dirfd,
                              const char* filename, const open_how& h,
                              CompletionToken&& completion_token) {
        auto [sqe, task] = ctx->get();
        io_uring_prep_openat2(sqe, dirfd, filename, const_cast<open_how*>(&h));
        task->__M_additional_val = reinterpret_cast<std::size_t>(f);

        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) mutable -> int {
                    auto* f = reinterpret_cast<file*>(self->__M_additional_val);
                    int res = get_res(self);
                    auto ec = get_ec(self);
                    if (!ec) {
                        f->set_fd(res);
                    }
                    token(ec);
                    return 0;
                },
                completion_token)),
            completion_token);
    }
};
}  // namespace chx::net::detail

template <typename CompletionToken>
decltype(auto)
chx::net::file::async_openat(const file_descriptor& dir, const char* filename,
                             const open_how& h,
                             CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::file_openat2>()(
        &get_associated_io_context(), this, dir.native_handler(), filename, h,
        detail::async_token_bind<const std::error_code&>(
            std::forward<CompletionToken>(completion_token)));
}
template <typename CompletionToken>
decltype(auto)
chx::net::file::async_openat(const file_descriptor& dir, const char* filename,
                             CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::file_openat2>()(
        &get_associated_io_context(), this, dir.native_handler(), filename,
        open_how{},
        detail::async_token_bind<const std::error_code&>(
            std::forward<CompletionToken>(completion_token)));
}
template <typename CompletionToken>
decltype(auto)
chx::net::file::async_openat(const char* filename, const open_how& h,
                             CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::file_openat2>()(
        &get_associated_io_context(), this, -1, filename, h,
        detail::async_token_bind<const std::error_code&>(
            std::forward<CompletionToken>(completion_token)));
}
template <typename CompletionToken>
decltype(auto)
chx::net::file::async_openat(const char* filename,
                             CompletionToken&& completion_token) {
    return detail::async_operation<detail::tags::file_openat2>()(
        &get_associated_io_context(), this, -1, filename, {},
        detail::async_token_bind<const std::error_code&>(
            std::forward<CompletionToken>(completion_token)));
}
