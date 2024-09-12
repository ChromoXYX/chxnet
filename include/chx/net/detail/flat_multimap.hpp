#pragma once

#include <algorithm>
#include <vector>
#include <optional>

namespace chx::net::detail {
template <typename ValueType, typename Compare>
struct key_compare_impl : Compare {
    template <typename K>
    constexpr bool operator()(const K& k, const ValueType& v) const
        noexcept(true) {
        return Compare::operator()(k, v.first);
    }
    template <typename K>
    constexpr bool operator()(const ValueType& v, const K& k) const
        noexcept(true) {
        return Compare::operator()(v.first, k);
    }
};

template <typename Key, typename Value, typename Compare = std::less<Key>>
class flat_multimap
    : protected key_compare_impl<std::pair<Key, Value>, Compare> {
  private:
    using cmp_type = key_compare_impl<std::pair<Key, Value>, Compare>;

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

    using key_compare = Compare;

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
        return std::lower_bound(c.begin(), c.end(), k, cmp());
    }
    template <typename K>
    const_iterator lower_bound(const K& k) const noexcept(true) {
        return std::lower_bound(c.begin(), c.end(), k, cmp());
    }
    template <typename K> iterator upper_bound(const K& k) noexcept(true) {
        return std::upper_bound(c.begin(), c.end(), k, cmp());
    }
    template <typename K>
    const_iterator upper_bound(const K& k) const noexcept(true) {
        return std::upper_bound(c.begin(), c.end(), k, cmp());
    }
    template <typename K> auto equal_range(const K& k) noexcept(true) {
        return std::equal_range(c.begin(), c.end(), k, cmp());
    }
    template <typename K> auto equal_range(const K& k) const noexcept(true) {
        return std::equal_range(c.begin(), c.end(), k, cmp());
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
    // template <typename K> size_type erase(const K& k) {
    //     auto [__begin, __tail] = equal_range(k);
    //     if (__begin != end() && key_comp()(__begin->first, k)) {
    //         const std::size_t s = __tail - __begin;
    //         erase(__tail, __begin);
    //         return s;
    //     } else {
    //         return 0;
    //     }
    // }
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

    constexpr const key_compare& key_comp() const noexcept(true) {
        return *this;
    }

  protected:
    container_type c;
    constexpr const cmp_type& cmp() { return *this; }
};
}  // namespace chx::net::detail