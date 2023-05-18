#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>

#include "./error_code.hpp"

namespace chx::net::ip {
/**
 * @brief Object which contains an IPv4 address.
 *
 */
class address_v4 {
    // always host byte order
    in_addr_t __M_raw = {};

  public:
    address_v4() = default;
    address_v4(const address_v4&) = default;
    address_v4(address_v4&&) = default;
    address_v4& operator=(const address_v4&) = default;
    address_v4& operator=(address_v4&&) = default;

    /**
     * @brief Construct a new address_v4 object from host byte order data.
     *
     */
    explicit constexpr address_v4(in_addr_t addr) noexcept : __M_raw(addr) {}
    /**
     * @brief Get underlying data in uint32_t.
     *
     * @note The address is in host byte order.
     *
     * @return constexpr std::uint32_t
     */
    constexpr std::uint32_t to_uint() const noexcept(true) { return __M_raw; }

    /**
     * @brief Assign contained address to the given address.
     *
     * @param addr
     */
    void assign(in_addr_t* addr) noexcept(true) { *addr = htonl(__M_raw); }

    constexpr bool is_loopback() const noexcept(true) {
        return (__M_raw & 0xFF000000) == 0x7F000000;
    }

    static address_v4 any() noexcept(true) { return address_v4{}; }

    std::string to_string() const {
        char buf[INET_ADDRSTRLEN] = {0};
        auto hr = htonl(__M_raw);
        auto* p = inet_ntop(AF_INET, &hr, buf, sizeof(buf));
        if (p) {
            return {p};
        } else {
            __CHXNET_THROW(errno);
        }
    }

    static address_v4 from_string(const char* cstr) {
        in_addr_t _r = {};
        if (inet_pton(AF_INET, cstr, &_r) == 1) {
            return address_v4{ntohl(_r)};
        } else {
            __CHXNET_THROW(EAFNOSUPPORT);
        }
    }
    static address_v4 from_string(const char* cstr,
                                  std::error_code& ec) noexcept(true) {
        in_addr_t _r = {};
        if (inet_pton(AF_INET, cstr, &_r) == 1) {
            ec.clear();
        } else {
            detail::assign_ec(ec, EAFNOSUPPORT);
        }
        return address_v4{ntohl(_r)};
    }

    static address_v4 from_string(const std::string& str) {
        return from_string(str.c_str());
    }
    static address_v4 from_string(const std::string& str,
                                  std::error_code& ec) noexcept(true) {
        return from_string(str.c_str(), ec);
    }
};

/**
 * @brief Object which contains an IPv6 address.
 *
 */
class address_v6 {
    static_assert(sizeof(in6_addr().s6_addr) == sizeof(in6_addr));

    in6_addr __M_raw;

  public:
    address_v6() = default;
    address_v6(const address_v6&) = default;
    address_v6(address_v6&&) = default;
    address_v6& operator=(const address_v6&) = default;
    address_v6& operator=(address_v6&&) = default;

    explicit constexpr address_v6(in6_addr addr) noexcept(true)
        : __M_raw(addr) {}
    constexpr in6_addr to_in6_addr() noexcept(true) { return __M_raw; }

    /**
     * @brief Assign contained address to the given address.
     *
     * @param addr
     */
    void assign(in6_addr* addr) noexcept(true) {
        memcpy(addr, &__M_raw, sizeof(__M_raw));
    }

    constexpr bool is_loopback() const noexcept(true) {
        return ((__M_raw.s6_addr[0] == 0) && (__M_raw.s6_addr[1] == 0) &&
                (__M_raw.s6_addr[2] == 0) && (__M_raw.s6_addr[3] == 0) &&
                (__M_raw.s6_addr[4] == 0) && (__M_raw.s6_addr[5] == 0) &&
                (__M_raw.s6_addr[6] == 0) && (__M_raw.s6_addr[7] == 0) &&
                (__M_raw.s6_addr[8] == 0) && (__M_raw.s6_addr[9] == 0) &&
                (__M_raw.s6_addr[10] == 0) && (__M_raw.s6_addr[11] == 0) &&
                (__M_raw.s6_addr[12] == 0) && (__M_raw.s6_addr[13] == 0) &&
                (__M_raw.s6_addr[14] == 0) && (__M_raw.s6_addr[15] == 1));
    }

    static address_v6 any() noexcept(true) { return address_v6{}; }

    std::string to_string() const {
        char buf[INET6_ADDRSTRLEN] = {0};
        auto* p = inet_ntop(AF_INET6, &__M_raw, buf, sizeof(buf));
        if (p) {
            return {p};
        } else {
            __CHXNET_THROW(errno);
        }
    }

    static address_v6 from_string(const char* cstr) {
        in6_addr _r;
        if (inet_pton(AF_INET6, cstr, &_r) == 1) {
            return address_v6{_r};
        } else {
            __CHXNET_THROW(EAFNOSUPPORT);
        }
    }
    static address_v6 from_string(const char* cstr,
                                  std::error_code& ec) noexcept(true) {
        in6_addr _r;
        if (inet_pton(AF_INET6, cstr, &_r) == 1) {
            ec.clear();
        } else {
            detail::assign_ec(ec, EAFNOSUPPORT);
        }
        return address_v6{_r};
    }

    static address_v6 from_string(const std::string& str) {
        return from_string(str.c_str());
    }
    static address_v6 from_string(const std::string& str,
                                  std::error_code& ec) noexcept(true) {
        return from_string(str.c_str(), ec);
    }
};

class address {
    static_assert(sizeof(address_v4) == sizeof(in_addr_t));
    static_assert(sizeof(address_v6) == sizeof(in6_addr));

    union {
        address_v4 v4;
        address_v6 v6;
    } __M_addr = {};
    int __M_family = AF_INET;

  public:
    address() = default;
    address(const address& other) = default;
    address& operator=(const address& other) = default;

    explicit constexpr address(int family) noexcept(true)
        : __M_family(family) {}
    constexpr address(const address_v4& addr)
        : __M_family(AF_INET), __M_addr{} {
        __M_addr.v4 = addr;
    }
    constexpr address(const address_v6& addr)
        : __M_family(AF_INET6), __M_addr{} {
        __M_addr.v6 = addr;
    }

    constexpr bool is_v4() const noexcept(true) {
        return __M_family == AF_INET;
    }
    constexpr bool is_v6() const noexcept(true) {
        return __M_family == AF_INET6;
    }
    constexpr int family() const noexcept(true) { return __M_family; }
    constexpr bool is_loopback() const noexcept(true) {
        if (is_v4()) {
            return __M_addr.v4.is_loopback();
        } else {
            return __M_addr.v6.is_loopback();
        }
    }

    address_v4 to_v4() const {
        if (is_v4()) {
            return __M_addr.v4;
        } else {
            __CHXNET_THROW(EINVAL);
        }
    }
    address_v6 to_v6() const {
        if (is_v6()) {
            return __M_addr.v6;
        } else {
            __CHXNET_THROW(EINVAL);
        }
    }

    std::string to_string() const {
        if (is_v4()) {
            return __M_addr.v4.to_string();
        } else {
            return __M_addr.v6.to_string();
        }
    }

    static address from_sockaddr(struct sockaddr* addr) noexcept(true) {
        if (addr->sa_family == AF_INET6) {
            auto* addr6 = reinterpret_cast<struct sockaddr_in6*>(addr);
            return address_v6(addr6->sin6_addr);
        } else {
            auto* addr4 = reinterpret_cast<struct sockaddr_in*>(addr);
            return address_v4(addr4->sin_addr.s_addr);
        }
    }
};

template <typename Protocol> struct basic_endpoint {
    ip::address __M_addr = {};
    unsigned short __M_port = {};

  public:
    basic_endpoint() = default;
    basic_endpoint(const basic_endpoint&) = default;
    basic_endpoint(basic_endpoint&&) = default;
    basic_endpoint& operator=(const basic_endpoint&) = default;
    basic_endpoint& operator=(basic_endpoint&&) = default;

    constexpr basic_endpoint(Protocol protocol,
                             unsigned short port) noexcept(true)
        : __M_addr(protocol.family()), __M_port(port) {}

    constexpr basic_endpoint(ip::address addr,
                             unsigned short port) noexcept(true)
        : __M_addr(addr), __M_port(port) {}

    constexpr ip::address address() const noexcept(true) { return __M_addr; }
    constexpr unsigned short port() const noexcept(true) { return __M_port; }
    constexpr void address(const ip::address& addr) noexcept(true) {
        __M_addr = addr;
    }
    constexpr void port(unsigned short port) noexcept(true) { __M_port = port; }

    Protocol protocol() const noexcept(true) {
        if (__M_addr.is_v4()) {
            return Protocol::v4();
        } else {
            return Protocol::v6();
        }
    }

    struct sockaddr_in sockaddr_in() const {
        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port());
        this->address().to_v4().assign(&addr.sin_addr.s_addr);
        return addr;
    }
    struct sockaddr_in6 sockaddr_in6() const {
        struct sockaddr_in6 addr = {};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port());
        this->address().to_v6().assign(&addr.sin6_addr);

        addr.sin6_flowinfo = 0;
        addr.sin6_scope_id = 0;
        return addr;
    }

    static basic_endpoint make_endpoint(struct sockaddr* addr) noexcept(true) {
        unsigned short port = 0;
        if (addr->sa_family == AF_INET6) {
            port = reinterpret_cast<struct sockaddr_in6*>(addr)->sin6_port;
        } else {
            port = reinterpret_cast<struct sockaddr_in*>(addr)->sin_port;
        }
        return basic_endpoint(address::from_sockaddr(addr), port);
    }
};
}  // namespace chx::net::ip
