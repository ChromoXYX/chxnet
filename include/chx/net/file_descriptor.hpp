#pragma once

#include "./io_context.hpp"
#include "./buffer.hpp"
#include "./detail/sfinae_placeholder.hpp"
#include "./impl/general_async_close.hpp"
#include "./buffer_sequence.hpp"
#include "./stream_base.hpp"

namespace chx::net {
class file_descriptor : public stream_base {
    CHXNET_NONCOPYABLE

    template <typename> friend struct detail::async_operation;

  public:
    constexpr file_descriptor(io_context& ctx, int fd = -1) noexcept(true)
        : stream_base(ctx, fd) {}
    file_descriptor(file_descriptor&& other) noexcept(true)
        : stream_base(std::move(other)) {}
    using stream_base::operator=;

    constexpr void set_fd(int new_fd) noexcept(true) { __M_fd = new_fd; }
    template <typename StreamIn, typename CompletionToken>
    decltype(auto) async_transfer(StreamIn&& stream_in, std::size_t total_size,
                                  std::size_t block_size,
                                  CompletionToken&& completion_token);
};

template <typename FileDescriptor, typename StreamIn, typename CompletionToken>
decltype(auto) async_transfer(
    FileDescriptor&& fd, StreamIn&& stream_in, std::size_t total_size,
    std::size_t block_size, CompletionToken&& completion_token,
    detail::sfinae_placeholder<std::enable_if_t<
        std::is_base_of_v<file_descriptor, std::decay_t<FileDescriptor>>>>
        _ = detail::sfinae);
}  // namespace chx::net

#include "./impl/file_descriptor.ipp"
