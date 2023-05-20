#pragma once

#include "../async_read.hpp"
#include "../async_read_until.hpp"

template <typename Stream, typename DynamicBuffer, typename CompletionToken>
decltype(auto) chx::net::async_read(Stream& stream,
                                    DynamicBuffer&& dynamic_buffer,
                                    CompletionToken&& completion_token) {
    struct cond {
        const std::size_t sz;

        constexpr std::size_t
        operator()(std::basic_string_view<unsigned char> v) noexcept(true) {
            return v.npos;
        }
        constexpr std::size_t extend_size() noexcept(true) { return sz; }
    };
    return async_read_until(stream, std::forward<DynamicBuffer>(dynamic_buffer),
                            cond{dynamic_buffer.max_size() < 8192
                                     ? dynamic_buffer.max_size()
                                     : 8192},
                            std::forward<CompletionToken>(completion_token));
}
