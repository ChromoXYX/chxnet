#pragma once

#include "../stream.hpp"
#include "./utility.hpp"

namespace chx::net::ssl::detail {
namespace tags {
struct ssl_write_seq {};
}  // namespace tags
}  // namespace chx::net::ssl::detail

template <>
struct chx::net::detail::async_operation<
    chx::net::ssl::detail::tags::ssl_write_seq> {
    template <typename Socket, typename IovArr> struct op {
        CHXNET_NONCOPYABLE

        template <typename CntlType> using rebind = op;

        ssl::stream<Socket>& self;
        IovArr iov_arr;
        std::size_t idx = 0;

        template <typename STRM, typename IA>
        op(STRM& strm, IA&& ia) : self(strm), iov_arr(std::forward<IA>(ia)) {}

        template <typename Cntl> void operator()(Cntl& cntl) {
            // assume no short write
            self.async_write_some(
                net::buffer(iov_arr[idx].iov_base, iov_arr[idx].iov_len),
                cntl.next());
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e, std::size_t) {
            ++idx;
            if (!e) {
                if (idx != std::size(iov_arr)) {
                    self.async_write_some(net::buffer(iov_arr[idx].iov_base,
                                                      iov_arr[idx].iov_len),
                                          cntl.next());
                } else {
                    std::size_t total = 0;
                    for (const struct iovec& iov : iov_arr) {
                        total += iov.iov_len;
                    }
                    cntl.complete(e, total);
                }
            } else {
                std::size_t total = 0;
                for (std::size_t i = 0; i < idx; ++i) {
                    total += iov_arr[i].iov_len;
                }
                cntl.complete(e, total);
            }
        }
    };
    template <typename Stream, typename IovArr>
    op(ssl::stream<Stream>&, IovArr&&)
        -> op<Stream,
              std::conditional_t<std::is_lvalue_reference_v<IovArr>, IovArr&&,
                                 std::remove_reference_t<IovArr>>>;
};

template <typename Socket>
template <typename IovArr, typename CompletionToken>
decltype(auto) chx::net::ssl::stream<Socket>::async_write_some(
    IovArr&& iov_arr, CompletionToken&& completion_token,
    net::detail::sfinae_placeholder<
        std::enable_if_t<!net::detail::is_const_buffer<IovArr>::value>>) {
    using operation_type =
        decltype(net::detail::async_operation<detail::tags::ssl_write_seq>::op(
            *this, std::forward<IovArr>(iov_arr)));
    return async_combine<const std::error_code&, std::size_t>(
        get_associated_io_context(),
        std::forward<CompletionToken>(completion_token),
        net::detail::type_identity<operation_type>{}, *this,
        std::forward<IovArr>(iov_arr));
}
