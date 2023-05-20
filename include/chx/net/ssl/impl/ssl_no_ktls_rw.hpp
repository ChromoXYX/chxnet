#pragma once

#include "./utility.hpp"

#include "../stream.hpp"

namespace chx::net::ssl::detail {
template <typename Stream, typename SSLOperation>
struct ssl_no_ktls_rw : SSLOperation {
    struct im_read {};
    struct final_write {};
    int current_ec = 0;
    int final_r = 0;

    template <typename... Args>
    ssl_no_ktls_rw(Stream* s, Args&&... args) noexcept(
        std::is_nothrow_constructible_v<SSLOperation, Args&&...>)
        : sock(s), SSLOperation(std::forward<Args>(args)...) {}

    using use_delivery =
        net::detail::async_operation<net::detail::tags::use_delivery>;

    Stream* const sock;

    template <typename Cntl> void perform_write(Cntl& cntl) {
        sock->lower_layer().async_write_some(net::buffer(sock->__M_out_buf),
                                             cntl.next());
        net::detail::async_operation<net::detail::tags::ssl_submit>()(
            &sock->get_associated_io_context());
        sock->__M_out_buf.clear();
    }

    template <typename Cntl> void perform(Cntl& cntl) {
        assert(cntl.tracked_task_num() == 0);
        ERR_clear_error();
        int r = SSLOperation::operator()(sock->get_associated_SSL());
        if (r > 0) {
            if (!sock->__M_out_buf.empty()) {
                final_r = r;
                sock->lower_layer().async_write_some(
                    net::buffer(sock->__M_out_buf),
                    cntl.template next_with_tag<final_write>());
                net::detail::async_operation<net::detail::tags::ssl_submit>()(
                    &sock->get_associated_io_context());
                sock->__M_out_buf.clear();
            } else {
                cntl.complete(std::error_code(), r);
            }
        } else {
            int current_ssl_ec = SSL_get_error(sock->get_associated_SSL(), r);
            if (current_ssl_ec == SSL_ERROR_WANT_READ) {
                sock->__M_in_buf.resize(Stream::read_buffer_max_size);
                sock->lower_layer().async_read_some(
                    net::buffer(sock->__M_in_buf),
                    cntl.template next_with_tag<im_read>());
                if (!sock->__M_out_buf.empty()) {
                    perform_write(cntl);
                }
            } else {
                cntl.complete(make_ssl_ec(current_ssl_ec), 0);
            }
        }
    }

    template <typename Cntl> void operator()(Cntl& cntl) { perform(cntl); }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, std::size_t s) {
        if (current_ec) {
            if (cntl.tracked_task_num() == 0) {
                cntl.complete(net::detail::make_ec(current_ec), 0);
            }
        } else if (e) {
            current_ec = e.value();
            if (cntl.tracked_task_num() == 0) {
                cntl.complete(net::detail::make_ec(current_ec), 0);
            }
        } else if (cntl.tracked_task_num() == 0) {
            perform(cntl);
        }
    }
    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, std::size_t s,
                    im_read) {
        if (!e) {
            sock->__M_in_buf.resize(s);
        }
        if (current_ec) {
            if (cntl.tracked_task_num() == 0) {
                cntl.complete(net::detail::make_ec(current_ec), 0);
            }
        } else if (e) {
            current_ec = e.value();
            if (cntl.tracked_task_num() == 0) {
                cntl.complete(net::detail::make_ec(current_ec), 0);
            }
        } else if (cntl.tracked_task_num() == 0) {
            perform(cntl);
        }
    }
    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, std::size_t s,
                    final_write) {
        cntl.complete(e, final_r);
    }
};
}  // namespace chx::net::ssl::detail
