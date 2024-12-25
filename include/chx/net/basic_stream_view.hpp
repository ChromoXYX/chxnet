#pragma once

#include <type_traits>
#include <utility>

namespace chx::net {
template <typename Stream> class basic_stream_view : public Stream {
  public:
    basic_stream_view(const basic_stream_view&) = default;
    basic_stream_view(basic_stream_view&&) = default;
    basic_stream_view(const Stream& strm) : Stream(strm) {}
    basic_stream_view(Stream&& strm) : Stream(std::move(strm)) {}

    using Stream::Stream;

    ~basic_stream_view() noexcept(std::is_nothrow_destructible_v<Stream>) {
        Stream::release();
    }
};
}  // namespace chx::net
