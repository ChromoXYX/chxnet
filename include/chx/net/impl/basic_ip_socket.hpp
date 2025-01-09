#pragma once

#include "../stream_base.hpp"

namespace chx::net::ip::detail {
template <typename Protocol> class basic_socket : public stream_base {
  public:
    using stream_base::stream_base;

    void open(const Protocol& protocol = Protocol::v4()) {
        if (is_open()) {
            close();
        }
        if (int new_fd = ::socket(protocol.family(), protocol.socket_type(), 0);
            new_fd > 0) {
            __M_fd = new_fd;
        } else {
            __CHXNET_THROW(errno);
        }
    }

    void open(const Protocol& protocol, std::error_code& ec) noexcept(true) {
        if (is_open()) {
            close(ec);
            if (ec) {
                return;
            }
        }
        if (int new_fd = ::socket(protocol.family(), protocol.socket_type(), 0);
            new_fd > 0) {
            __M_fd = new_fd;
            ec.clear();
        } else {
            net::assign_ec(ec, errno);
        }
    }

    void bind(const typename Protocol::endpoint& ep) {
        if (ep.address().is_v4()) {
            struct sockaddr_in sar = ep.sockaddr_in();
            if (::bind(__M_fd, reinterpret_cast<sockaddr*>(&sar),
                       sizeof(sar)) == -1) {
                __CHXNET_THROW(errno);
            }
        } else {
            struct sockaddr_in6 sar = ep.sockaddr_in6();
            if (::bind(__M_fd, reinterpret_cast<sockaddr*>(&sar),
                       sizeof(sar)) == -1) {
                __CHXNET_THROW(errno);
            }
        }
    }

    void bind(const typename Protocol::endpoint& ep,
              std::error_code& ec) noexcept(true) {
        if (ep.address().is_v4()) {
            struct sockaddr_in sar = ep.sockaddr_in();
            if (::bind(__M_fd, reinterpret_cast<sockaddr*>(&sar),
                       sizeof(sar)) == -1) {
                net::assign_ec(ec, errno);
                return;
            }
        } else {
            struct sockaddr_in6 sar = ep.sockaddr_in6();
            if (::bind(__M_fd, reinterpret_cast<sockaddr*>(&sar),
                       sizeof(sar)) == -1) {
                net::assign_ec(ec, errno);
                return;
            }
        }
    }

    typename Protocol::endpoint local_endpoint(std::error_code& e) const
        noexcept(true) {
        alignas(struct sockaddr_in6) unsigned char buffer[64] = {};
        socklen_t len = sizeof(buffer);
        if (getsockname(native_handler(),
                        reinterpret_cast<struct sockaddr*>(buffer),
                        &len) == 0) {
            return Protocol::endpoint::make_endpoint(
                reinterpret_cast<struct sockaddr*>(buffer));
        } else {
            assign_ec(e, errno);
            return {};
        }
    }
    typename Protocol::endpoint local_endpoint() const {
        std::error_code e;
        typename Protocol::endpoint ep = local_endpoint(e);
        if (!e) {
            return std::move(ep);
        } else {
            __CHXNET_THROW_EC(e);
        }
    }

    typename Protocol::endpoint remote_endpoint(std::error_code& e) const
        noexcept(true) {
        alignas(struct sockaddr_in6) unsigned char buffer[64] = {};
        socklen_t len = sizeof(buffer);
        if (getpeername(native_handler(),
                        reinterpret_cast<struct sockaddr*>(buffer),
                        &len) == 0) {
            return Protocol::endpoint::make_endpoint(
                reinterpret_cast<struct sockaddr*>(buffer));
        } else {
            assign_ec(e, errno);
            return {};
        }
    }
    typename Protocol::endpoint remote_endpoint() const {
        std::error_code e;
        typename Protocol::endpoint ep = remote_endpoint(e);
        if (!e) {
            return std::move(ep);
        } else {
            __CHXNET_THROW_EC(e);
        }
    }
};
}  // namespace chx::net::ip::detail