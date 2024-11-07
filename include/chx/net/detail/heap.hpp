#pragma once

#include <queue>

namespace chx::net::detail {
template <typename K, typename V, typename KeyCompare>
struct key_compare_to_value_compare : KeyCompare {
    using __value_type = std::pair<K, V>;
    constexpr bool operator()(const __value_type& a,
                              const __value_type& b) const
        noexcept(noexcept(KeyCompare::operator()(a.first, b.first))) {
        return KeyCompare::operator()(a.first, b.first);
    }
};

template <typename Key, typename Value, typename KeyCompare = std::less<Key>,
          typename Allocator = std::allocator<std::pair<Key, Value>>>
class heap
    : public std::priority_queue<
          std::pair<Key, Value>, std::vector<std::pair<Key, Value>, Allocator>,
          key_compare_to_value_compare<Key, Value, KeyCompare>> {
    using __container = std::priority_queue<
        std::pair<Key, Value>, std::vector<std::pair<Key, Value>, Allocator>,
        key_compare_to_value_compare<Key, Value, KeyCompare>>;

  public:
    using key_type = Key;
    using mapped_type = Value;
    using iterator = typename __container::container_type::iterator;
    using const_iterator = typename __container::container_type::const_iterator;

    constexpr iterator begin() noexcept(true) { return __container::c.begin(); }
    constexpr iterator end() noexcept(true) { return __container::c.end(); }
    constexpr iterator begin() const noexcept(true) {
        return __container::c.begin();
    }
    constexpr iterator end() const noexcept(true) {
        return __container::c.end();
    }
};
}  // namespace chx::net::detail
