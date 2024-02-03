#pragma once

#include <algorithm>
#include <vector>
#include <optional>

namespace chx::net::detail {
template <typename Key, typename Value> class flat_multimap {
  public:
    using key_type = Key;
    using mapped_type = Value;
    using value_type = std::pair<key_type, mapped_type>;
    using container_type = std::vector<value_type>;
    using iterator = typename container_type::iterator;
    using const_iterator = typename container_type::const_iterator;
    using reference = typename container_type::reference;
    using const_reference = typename container_type::const_reference;
    using size_type = typename container_type::size_type;

    template <typename K> struct key_compare {
        constexpr bool operator()(const K& k, const value_type& v) const
            noexcept(true) {
            return k < v.first;
        }
        constexpr bool operator()(const value_type& v, const K& k) const
            noexcept(true) {
            return v.first < k;
        }
    };

    struct node_type {
        friend class flat_multimap;

        node_type() = default;
        node_type(node_type&&) = default;
        node_type(value_type&& v) : __M_v(std::move(v)) {}

        bool empty() const noexcept(true) { return !__M_v.has_value(); }
        operator bool() const noexcept(true) { return __M_v.has_value(); }

        key_type& key() const noexcept(true) {
            return const_cast<key_type&>(__M_v.value().first);
        }
        mapped_type& mapped() const noexcept(true) {
            return const_cast<mapped_type&>(__M_v.value().second);
        }

      private:
        std::optional<value_type> __M_v;
    };

    template <typename K> iterator lower_bound(const K& k) noexcept(true) {
        return std::lower_bound(c.begin(), c.end(), k, key_compare<K>{});
    }
    template <typename K>
    const_iterator lower_bound(const K& k) const noexcept(true) {
        return std::lower_bound(c.begin(), c.end(), k, key_compare<K>{});
    }
    template <typename K> iterator upper_bound(const K& k) noexcept(true) {
        return std::upper_bound(c.begin(), c.end(), k, key_compare<K>{});
    }
    template <typename K>
    const_iterator upper_bound(const K& k) const noexcept(true) {
        return std::upper_bound(c.begin(), c.end(), k, key_compare<K>{});
    }
    template <typename K> auto equal_range(const K& k) noexcept(true) {
        return std::equal_range(c.begin(), c.end(), k, key_compare<K>{});
    }
    template <typename K> auto equal_range(const K& k) const noexcept(true) {
        return std::equal_range(c.begin(), c.end(), k, key_compare<K>{});
    }

    iterator insert(value_type&& v) {
        return c.insert(upper_bound(v.first), std::move(v));
    }
    iterator insert(node_type&& nh) {
        if (nh) {
            return insert(std::move(nh.__M_v.value()));
        } else {
            return c.end();
        }
    }
    // not so emplace...
    template <typename... Ts> reference emplace(Ts&&... ts) {
        return *insert(value_type{std::forward<Ts>(ts)...});
    }

    iterator erase(iterator pos) { return c.erase(pos); }
    iterator erase(iterator first, iterator last) {
        return c.erase(first, last);
    }
    template <typename K> size_type erase(const K& k) {
        auto _r = equal_range(k);
        std::size_t s = _r.second - _r.first;
        erase(_r.first, _r.second);
        return s;
    }
    node_type extract(iterator ite) {
        node_type nh(std::move(*ite));
        erase(ite);
        return std::move(nh);
    }

    void clear() noexcept(true) { c.clear(); }
    constexpr std::size_t size() const noexcept(true) { return c.size(); }

    constexpr iterator begin() noexcept(true) { return c.begin(); }
    constexpr iterator end() noexcept(true) { return c.end(); }
    constexpr const_iterator begin() const noexcept(true) { return c.begin(); }
    constexpr const_iterator end() const noexcept(true) { return c.end(); }

    template <typename K1, typename K2, typename Fn>
    void consume_range(const K1& low, const K2& high, Fn&& fn) {
        if (auto ite = upper_bound(low); ite != c.end()) {
            auto ite2 = lower_bound(high);
            container_type _r(std::make_move_iterator(ite),
                              std::make_move_iterator(ite2));
            erase(ite, ite2);
            for (auto& v : _r) {
                std::forward<Fn>(fn)(v);
            }
        }
    }

  protected:
    container_type c;
};
}  // namespace chx::net::detail