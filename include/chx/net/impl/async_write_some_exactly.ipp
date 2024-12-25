#pragma once

#include "../async_combine.hpp"
#include "../async_write_some_exactly.hpp"
#include "../io_context.hpp"
#include "../buffer.hpp"
#include "../detail/type_identity.hpp"

namespace chx::net::detail {
namespace tags {
struct write_some_exactly {};
}  // namespace tags

template <> struct async_operation<tags::write_some_exactly> {
    template <typename Stream, typename Container> struct operation {
        template <typename CntlType> using rebind = operation;

        Stream stream;
        Container container;
        const unsigned char* begin = nullptr;
        std::size_t transferred = 0;

        template <typename S, typename C>
        operation(S&& s, C&& c)
            : stream(std::forward<S>(s)), container(std::forward<C>(c)),
              begin(static_cast<const unsigned char*>(
                  net::buffer(container).data())) {}

        template <typename Cntl> void operator()(Cntl& cntl) {
            stream.async_write_some(net::buffer(begin, std::size(container)),
                                    cntl.next());
        }
        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e, std::size_t s) {
            if (!e && s) {
                if (transferred + s < std::size(container)) {
                    begin += s;
                    transferred += s;
                    stream.async_write_some(
                        net::buffer(begin, std::size(container) - transferred),
                        cntl.next());
                } else {
                    cntl.complete(e, transferred + s);
                }
            } else {
                cntl.complete(e, transferred);
            }
        }
    };
    template <typename Stream, typename Container>
    operation(Stream&&, Container&&) -> operation<
        std::conditional_t<std::is_lvalue_reference_v<Stream&&>, Stream&&,
                           std::remove_reference_t<Stream&&>>,
        std::conditional_t<std::is_lvalue_reference_v<Container&&>, Container&&,
                           std::remove_reference_t<Container&&>>>;
};
}  // namespace chx::net::detail

template <typename Stream, typename Container, typename CompletionToken>
decltype(auto)
chx::net::async_write_some_exactly(Stream&& stream, Container&& container,
                                   CompletionToken&& completion_token) {
    using operation_type =
        decltype(detail::async_operation<detail::tags::write_some_exactly>::
                     operation(std::forward<Stream>(stream),
                               std::forward<Container>(container)));
    return async_combine<const std::error_code&, std::size_t>(
        stream.get_associated_io_context(),
        std::forward<CompletionToken>(completion_token),
        detail::type_identity<operation_type>(), std::forward<Stream>(stream),
        std::forward<Container>(container));
}
