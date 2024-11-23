#pragma once

#include "../async_read_until.hpp"
#include "./general_io.hpp"

template <typename Stream, typename DynamicBuffer, typename StopCondition,
          typename CompletionToken>
decltype(auto) chx::net::async_read_until(Stream& stream,
                                          DynamicBuffer&& dynamic_buffer,
                                          StopCondition&& stop_condition,
                                          CompletionToken&& completion_token) {
    return net::detail::async_operation<detail::tags::read_until>()(
        &stream.get_associated_io_context(), &stream,
        std::forward<DynamicBuffer>(dynamic_buffer),
        std::forward<StopCondition>(stop_condition),
        std::forward<CompletionToken>(completion_token));
}

template <typename Stream, typename StopCondition, typename CompletionToken>
decltype(auto) chx::net::async_read_until(Stream& stream,
                                          StopCondition&& stop_condition,
                                          CompletionToken&& completion_token) {
    return net::detail::async_operation<detail::tags::read_until>()(
        &stream.get_associated_io_context(), &stream,
        std::forward<StopCondition>(stop_condition),
        std::forward<CompletionToken>(completion_token));
}
