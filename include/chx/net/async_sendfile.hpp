#pragma once

#include "./async_combine.hpp"

namespace chx::net {
namespace detail {
namespace tags {
struct async_sendfile {};
struct async_sendfile_splice {};
}  // namespace tags

template <> struct async_operation<tags::async_sendfile_splice> {
    template <typename CompletionToken>
    decltype(auto) operator()(io_context* ctx, int fd_in, int fd_out,
                              std::size_t sz,
                              CompletionToken&& completion_token) const {
        return oper(ctx, fd_in, fd_out, sz,
                    async_token_bind<const std::error_code&, std::size_t>(
                        std::forward<CompletionToken>(completion_token)));
    }
    template <typename CompletionToken>
    decltype(auto) oper(io_context* ctx, int fd_in, int fd_out, std::size_t sz,
                        CompletionToken&& completion_token) const {
        auto [sqe, task] = ctx->get();
        io_uring_prep_splice(sqe, fd_in, -1, fd_out, -1, sz, 0);
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

template <> struct async_operation<tags::async_sendfile> {
    template <typename File, typename StreamRef, typename CntlType = void>
    struct operation {
        CHXNET_NONCOPYABLE

        template <typename T> using rebind = operation<File, StreamRef, T>;

        File file;
        StreamRef stream_ref;
        std::size_t remain_size = 0;
        std::size_t transfer = 0;
        int pipe_capacity = 0;
        enum Turn : int { in, out } turn;
        int pipes[2] = {};

        template <typename F, typename S>
        operation(F&& f, S&& s, std::size_t sz)
            : file(std::forward<F>(f)), stream_ref(std::forward<S>(s)),
              remain_size(sz), turn(in) {}

        ~operation() {
            ::close(pipes[0]);
            ::close(pipes[1]);
        }

        template <typename Cntl> void perform(Cntl& cntl) {
            switch (turn) {
            case in: {
                return async_operation<tags::async_sendfile_splice>()(
                    &file.get_associated_io_context(), file.native_handler(),
                    pipes[1],
                    remain_size > pipe_capacity ? pipe_capacity : remain_size,
                    cntl.next());
            }
            case out: {
                return async_operation<tags::async_sendfile_splice>()(
                    &file.get_associated_io_context(), pipes[0],
                    stream_ref.native_handler(), pipe_capacity, cntl.next());
            }
            }
        }

        template <typename Cntl> void operator()(Cntl& cntl) {
            static_assert(!std::is_same_v<CntlType, void>);
            if (pipe(pipes) == 0 &&
                (pipe_capacity = ::fcntl(pipes[0], F_GETPIPE_SZ)) != -1) {
                return perform(cntl);
            } else {
                return async_operation<tags::use_delivery>()
                    .oper<const std::error_code&, std::size_t>(
                        &file.get_associated_io_context(),
                        [e = errno](auto& token,
                                    io_context::task_t* self) mutable -> int {
                            token(make_ec(e), 0);
                            return 0;
                        },
                        cntl.next());
            }
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e, std::size_t s) {
            if (!e) {
                if (remain_size == 0 || s == 0) {
                    return cntl.complete(e, transfer);
                }
                switch (turn) {
                case in: {
                    turn = out;
                    break;
                }
                case out: {
                    turn = in;
                    transfer += s;
                    remain_size -= s;
                    break;
                }
                }
                perform(cntl);
            } else {
                return cntl.complete(e, s);
            }
        }
    };
    template <typename File, typename Stream>
    operation(File&&, Stream&, std::size_t) -> operation<File, Stream&>;
    template <typename File, typename Stream>
    operation(File&, Stream&, std::size_t) -> operation<File&, Stream&>;
};
}  // namespace detail

template <typename File, typename Stream, typename CompletionToken>
decltype(auto) async_sendfile(File&& file, Stream& stream,
                              std::size_t file_size,
                              CompletionToken&& completion_token) {
    using operation_type =
        decltype(detail::async_operation<detail::tags::async_sendfile>::
                     operation(std::forward<File>(file), stream, file_size));
    return async_combine<const std::error_code&, std::size_t>(
        file.get_associated_io_context(),
        std::forward<CompletionToken>(completion_token),
        detail::type_identity<operation_type>(), std::forward<File>(file),
        stream, file_size);
}
}  // namespace chx::net
