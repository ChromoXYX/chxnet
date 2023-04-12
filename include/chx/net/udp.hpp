#pragma once

#include "./ip.hpp"

namespace chx::net::ip {
class udp {
  public:
    class socket;

    constexpr udp(int family) noexcept(true) : __M_family(family) {}

    constexpr int family() const noexcept(true) { return __M_family; }

    static constexpr int socket_type() noexcept(true) { return SOCK_DGRAM; }
    static constexpr udp v4() noexcept(true) { return udp(AF_INET); }
    static constexpr udp v6() noexcept(true) { return udp(AF_INET6); }

    using endpoint = basic_endpoint<udp>;

  private:
    int __M_family;
};
}  // namespace chx::net::ip

#include "./impl/udp_socket.ipp"
