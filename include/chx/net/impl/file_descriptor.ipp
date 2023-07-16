#pragma once

#include "../file_descriptor.hpp"

#include "../async_combine.hpp"

namespace chx::net::detail {
namespace tags {
struct fd_read {};
struct fd_write {};
struct fd_transfer {};
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
                    token(self->__M_res != 0 ? self->__M_ec
                                             : make_ec(errc::eof),
                          self->__M_res);
                    return 0;
                },
                completion_token)),
            completion_token);
    }
    template <typename CompletionToken>
    decltype(auto) os(file_descriptor* fd, const mutable_buffer& mutable_buffer,
                      std::size_t offset, CompletionToken&& completion_token) {
        auto [sqe, task] = fd->get_associated_io_context().get();

        io_uring_prep_read(sqe, fd->native_handler(), mutable_buffer.data(),
                           mutable_buffer.size(), offset);
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, io_context::task_t* self) mutable -> int {
                    token(self->__M_res != 0 ? self->__M_ec
                                             : make_ec(errc::eof),
                          self->__M_res);
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

template <> struct async_operation<tags::fd_transfer> {
    template <typename FileDescriptor, typename StreamIn> struct operation {
        struct read {};
        struct write {};

        std::vector<unsigned char> buffer;
        FileDescriptor fd;
        StreamIn stream_in;
        std::size_t transferred_size = 0;
        std::size_t remain_size;

        template <typename FD, typename SI>
        operation(FD&& f, SI&& s, std::size_t total_size,
                  std::size_t block_size)
            : fd(std::forward<FD>(f)), stream_in(std::forward<SI>(s)),
              remain_size(total_size), buffer(block_size) {}

        template <typename Cntl> void perform_read(Cntl& cntl) {
            fd.async_read_some(
                net::buffer(buffer, std::min(buffer.size(), remain_size)),
                transferred_size, cntl.template next_with_tag<read>());
        }
        template <typename Cntl> void perform_write(Cntl& cntl, std::size_t s) {
            stream_in.async_write_some(net::buffer(buffer, s),
                                       cntl.template next_with_tag<write>());
        }

        template <typename Cntl> void operator()(Cntl& cntl) {
            perform_read(cntl);
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e, std::size_t s,
                        read) {
            if (!e) {
                perform_write(cntl, s);
            } else {
                cntl.complete(e, transferred_size);
            }
        }
        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e, std::size_t s,
                        write) {
            if (!e) {
                transferred_size += s;
                remain_size -= s;
                if (remain_size != 0) {
                    perform_read(cntl);
                } else {
                    cntl.complete(e, transferred_size);
                }
            } else {
                cntl.complete(e, transferred_size);
            }
        }
    };
    template <typename FileDescriptor, typename StreamIn>
    operation(FileDescriptor&&, StreamIn&&, std::size_t, std::size_t)
        -> operation<
            std::conditional_t<std::is_lvalue_reference_v<FileDescriptor&&>,
                               FileDescriptor&&,
                               std::remove_reference_t<FileDescriptor&&>>,
            std::conditional_t<std::is_lvalue_reference_v<StreamIn&&>,
                               StreamIn&&,
                               std::remove_reference_t<StreamIn&&>>>;
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

template <typename MutableBuffer, typename CompletionToken>
decltype(auto) chx::net::file_descriptor::async_read_some(
    MutableBuffer&& mutable_buffer, std::size_t offset,
    CompletionToken&& completion_token,
    detail::sfinae_placeholder<
        std::enable_if_t<detail::is_mutable_buffer<MutableBuffer>::value>>) {
    return detail::async_operation<detail::tags::fd_read>().os(
        this, mutable_buffer, offset,
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

template <typename FileDescriptor, typename StreamIn, typename CompletionToken>
decltype(auto) chx::net::async_transfer(
    FileDescriptor&& fd, StreamIn&& stream_in, std::size_t total_size,
    std::size_t block_size, CompletionToken&& completion_token,
    detail::sfinae_placeholder<std::enable_if_t<
        std::is_base_of_v<file_descriptor, std::decay_t<FileDescriptor>>>>) {
    using operation_type =
        decltype(detail::async_operation<detail::tags::fd_transfer>::operation(
            std::forward<FileDescriptor>(fd), std::forward<StreamIn>(stream_in),
            total_size, block_size));
    return async_combine<const std::error_code&, std::size_t>(
        fd.get_associated_io_context(),
        std::forward<CompletionToken>(completion_token),
        detail::type_identity<operation_type>{},
        std::forward<FileDescriptor>(fd), std::forward<StreamIn>(stream_in),
        total_size, block_size);
}

template <typename StreamIn, typename CompletionToken>
decltype(auto) chx::net::file_descriptor::async_transfer(
    StreamIn&& stream_in, std::size_t total_size, std::size_t block_size,
    CompletionToken&& completion_token) {
    return net::async_transfer(*this, std::forward<StreamIn>(stream_in),
                               total_size, block_size,
                               std::forward<CompletionToken>(completion_token));
}
