#pragma once

#include "../detail/noncopyable.hpp"
#include "../type_traits/flatten_sequence.hpp"
#include "../detail/span.hpp"

namespace chx::net::detail {
template <typename RealSequence, typename Derived> struct write_exactly {
    CHXNET_NONCOPYABLE

    constexpr Derived* derived() noexcept(true) {
        return static_cast<Derived*>(this);
    }

    using __toolkit = flatten_sequence_impl;

    template <typename RS>
    write_exactly(RS&& rs)
        : __M_real_seq(std::forward<RS>(rs)),
          __M_flat_sequence(flatten_sequence(__M_real_seq)) {
        for (const iovec& i : __M_flat_sequence) {
            __M_total_size += i.iov_len;
        }
    }

    template <typename Cntl> void operator()(Cntl& cntl) {
        derived()->do_write(__M_flat_sequence);
    }
    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, std::size_t s) {
        if (!e && s) {
            if (__M_transferred + s < __M_total_size) {
                __M_transferred += s;
                while (__M_iovec_index < __M_flat_sequence.size() &&
                       s >= __M_flat_sequence[__M_iovec_index].iov_len) {
                    s -= __M_flat_sequence[__M_iovec_index++].iov_len;
                }
                assert(__M_iovec_index < __M_flat_sequence.size() &&
                       __M_flat_sequence[__M_iovec_index].iov_len > s);
                __M_flat_sequence[__M_iovec_index].iov_len -= s;
                span sp(__M_flat_sequence.data() + __M_iovec_index,
                        __M_flat_sequence.size() - __M_iovec_index);
                derived()->do_write(sp);
            } else {
                cntl.complete(e, __M_total_size);
            }
        } else {
            cntl.complete(e, __M_transferred);
        }
    }

  private:
    RealSequence __M_real_seq;

    flatten_sequence_type<RealSequence> __M_flat_sequence;
    std::size_t __M_transferred = 0;
    std::size_t __M_total_size = 0;
    std::size_t __M_iovec_index = 0;
};
}  // namespace chx::net::detail
