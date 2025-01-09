#pragma once

#include "../file_descriptor.hpp"

#include "../async_combine.hpp"
#include "./general_io.hpp"

namespace chx::net::detail {
namespace tags {
struct fd_transfer {};
}  // namespace tags

template <> struct async_operation<tags::fd_transfer> {
    template <typename FileDescriptor, typename StreamIn,
              typename CntlType = void>
    struct operation {
        struct read {};
        struct write {};

        template <typename T>
        using rebind = operation<FileDescriptor, StreamIn, T>;

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
            static_assert(!std::is_same_v<CntlType, void>);
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
