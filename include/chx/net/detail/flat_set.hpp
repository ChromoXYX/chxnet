#pragma once

#include <algorithm>
#include <vector>

namespace chx::net::detail {
template <typename Key, typename Compare = std::less<Key>>
class flat_set : Compare {
  public:
    using value_type = Key;

  private:
    using __container_type = std::vector<value_type>;
    __container_type __M_c;

    template <typename T, typename R>
    constexpr bool __equal(T&& t, R&& r) const noexcept(true) {
        return !(static_cast<const Compare&>(*this)(t, r)) &&
               !(static_cast<const Compare&>(*this)(r, t));
    }

  public:
    using iterator = typename __container_type::iterator;
    using const_iterator = typename __container_type::const_iterator;
    using reference = typename __container_type::reference;
    using const_reference = typename __container_type::const_reference;
    using size_type = typename __container_type::size_type;
    using difference_type = typename __container_type::difference_type;
    using key_compare = Compare;
    using pointer = typename __container_type::pointer;

    flat_set() = default;
    flat_set(const flat_set&) = default;
    flat_set(flat_set&&) = default;
    flat_set& operator=(const flat_set&) = default;
    flat_set& operator=(flat_set&&) = default;

    constexpr iterator begin() noexcept(true) { return __M_c.begin(); }
    constexpr iterator begin() const noexcept(true) { return __M_c.begin(); }
    constexpr iterator end() noexcept(true) { return __M_c.end(); }
    constexpr iterator end() const noexcept(true) { return __M_c.end(); }

    constexpr std::size_t size() const noexcept(true) { return __M_c.size(); }
    constexpr bool empty() const noexcept(true) { return __M_c.empty(); }
    void clear() noexcept(true) { __M_c.clear(); }

    template <typename K> constexpr iterator find(K&& k) noexcept(true) {
        auto __front = lower_bound(std::forward<K>(k));
        if (__front == end() || (!__equal(std::forward<K>(k), *__front))) {
            return end();
        } else {
            return __front;
        }
    }

    template <typename K> constexpr iterator lower_bound(K&& k) noexcept(true) {
        return std::lower_bound(begin(), end(), std::forward<K>(k),
                                static_cast<Compare&>(*this));
    }
    template <typename K>
    constexpr const_iterator lower_bound(K&& k) const noexcept(true) {
        return std::lower_bound(begin(), end(), std::forward<K>(k),
                                static_cast<Compare&>(*this));
    }

    template <typename K> constexpr iterator upper_bound(K&& k) noexcept(true) {
        return std::upper_bound(begin(), end(), std::forward<K>(k),
                                static_cast<Compare&>(*this));
    }
    template <typename K>
    constexpr const_iterator upper_bound(K&& k) const noexcept(true) {
        return std::upper_bound(begin(), end(), std::forward<K>(k),
                                static_cast<Compare&>(*this));
    }

    template <typename K>
    constexpr std::pair<iterator, iterator> equal_range(K&& k) noexcept(true) {
        return std::equal_range(begin(), end(), std::forward<K>(k),
                                static_cast<Compare&>(*this));
    }
    template <typename K>
    constexpr std::pair<const_iterator, const_iterator> equal_range(K&& k) const
        noexcept(true) {
        return std::equal_range(begin(), end(), std::forward<K>(k),
                                static_cast<Compare&>(*this));
    }

    template <typename T> std::pair<iterator, bool> insert(T&& t) {
        auto [__front, __tail] = equal_range(std::forward<T>(t));
        if (__front == end() || !__equal(std::forward<T>(t), *__front)) {
            return {__M_c.insert(__front, std::forward<T>(t)), true};
        } else {
            return {__front, false};
        }
    }

    iterator erase(iterator pos) {
        return pos != end() ? __M_c.erase(pos) : pos;
    }
    iterator erase(iterator __front, iterator __end) {
        return __M_c.erase(__front, __end);
    }
    template <typename K> size_type erase(K&& k) {
        auto [__front, __tail] = equal_range(std::forward<K>(k));
        if (__front != end()) {
            __M_c.erase(__front, __tail);
            return __tail - __front;
        } else {
            return 0;
        }
    }

    template <typename K> constexpr std::size_t count(K&& k) const {
        auto [__front, __tail] = equal_range(std::forward<K>(k));
        return __tail - __front;
    }
    template <typename K> constexpr bool contains(K&& k) const {
        return std::binary_search(begin(), end(), std::forward<K>(k),
                                  static_cast<Compare&>(*this));
    }

    value_type extract(iterator pos) {
        value_type r = std::move(*pos);
        erase(pos);
        return std::move(r);
    }
};
}  // namespace chx::net::detail