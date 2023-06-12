#pragma once

#include "../stream.hpp"

namespace chx::net::ssl::detail::tags {
struct write_some {};
}  // namespace chx::net::ssl::detail::tags

template <>
struct chx::net::detail::async_operation<
    chx::net::ssl::detail::tags::write_some> {
    template <typename StreamRef, typename ConstBufferSequence>
    struct operation {
        StreamRef stream_ref;
        ConstBufferSequence const_buffer_sequence;
        decltype(std::begin(const_buffer_sequence)) begin, end;
        std::size_t count = 0;

        template <typename SR, typename CBS>
        operation(SR&& sr, CBS&& cbs)
            : stream_ref(std::forward<SR>(sr)),
              const_buffer_sequence(std::forward<CBS>(cbs)),
              begin(std::begin(const_buffer_sequence)),
              end(std::end(const_buffer_sequence)) {}

        template <typename Cntl> void operator()(Cntl& cntl) {
            if (begin != end) {
                stream_ref.async_write_some(*(begin++), cntl.next());
            }
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e, std::size_t s) {
            count += s;
            if (!e && begin != end) {
                stream_ref.async_write_some(*(begin++), cntl.next());
            } else {
                cntl.complete(e, count);
            }
        }
    };
    template <typename StreamRef, typename ConstBufferSequence>
    operation(StreamRef&, ConstBufferSequence&&)
        -> operation<StreamRef&, std::decay_t<ConstBufferSequence>>;
};

template <typename Socket>
template <typename ConstBufferSequence, typename CompletionToken>
decltype(auto) chx::net::ssl::stream<Socket>::async_write_some(
    ConstBufferSequence&& const_buffer_sequence,
    CompletionToken&& completion_token,
    net::detail::sfinae_placeholder<std::enable_if_t<is_const_buffer_sequence<
        std::remove_reference_t<ConstBufferSequence>>::value>>) {
    using operation_type =
        decltype(net::detail::async_operation<
                 net::ssl::detail::tags::write_some>::
                     operation(*this, std::forward<ConstBufferSequence>(
                                          const_buffer_sequence)));
    return async_combine<const std::error_code&, std::size_t>(
        get_associated_io_context(),
        std::forward<CompletionToken>(completion_token),
        net::detail::type_identity<operation_type>(), *this,
        std::forward<ConstBufferSequence>(const_buffer_sequence));
}
