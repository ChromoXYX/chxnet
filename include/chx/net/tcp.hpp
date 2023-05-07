#pragma once

#include "./ip.hpp"
#include "./error_code.hpp"
#include "./basic_socket.hpp"

namespace chx::net::ip {

class tcp {
  public:
    using socket_base = basic_socket<tcp>;
    class socket;
    class acceptor;

    constexpr tcp(int family) noexcept(true) : __M_family(family) {}

    constexpr int family() const noexcept(true) { return __M_family; }

    static constexpr int socket_type() noexcept(true) { return SOCK_STREAM; }
    static constexpr tcp v4() noexcept(true) { return tcp(AF_INET); }
    static constexpr tcp v6() noexcept(true) { return tcp(AF_INET6); }

    using endpoint = basic_endpoint<tcp>;

  private:
    int __M_family;
};
}  // namespace chx::net::ip

#include "./impl/tcp_socket.ipp"
#include "./impl/tcp_acceptor.ipp"
