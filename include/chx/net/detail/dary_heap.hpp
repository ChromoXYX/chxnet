#pragma once

#include <vector>
#include <algorithm>

namespace chx::net::detail {
namespace d_ary {
template <std::size_t D>
constexpr std::size_t child(std::size_t i, std::size_t k) noexcept(true) {
    return i * D + k + 1;
}
template <std::size_t D>
constexpr std::size_t parent(std::size_t i) noexcept(true) {
    return (i - 1) / D;
}

template <std::size_t D, typename RandomIt, typename Compare>
void sift_up(RandomIt begin, std::size_t pos, const Compare& comp) {
    while (pos > 0 && !comp(*(begin + parent<D>(pos)), *(begin + pos))) {
        std::swap(*(begin + parent<D>(pos)), *(begin + pos));
        pos = parent<D>(pos);
    }
}
template <std::size_t D, typename RandomIt, typename Compare>
void sift_down(RandomIt begin, RandomIt end, std::size_t pos,
               const Compare& comp) {
    const std::size_t n = std::distance(begin, end);
    for (;;) {
        std::size_t min_index = pos;
        for (std::size_t k = 0; k < D; ++k) {
            std::size_t ch = child<D>(pos, k);
            if (ch < n && !comp(*(begin + min_index), *(begin + ch))) {
                min_index = ch;
            }
        }
        if (min_index != pos) {
            std::swap(*(begin + min_index), *(begin + pos));
            pos = min_index;
        } else {
            break;
        }
    }
}

template <typename Key, typename Value, typename KeyCompare>
struct key_compare_to_value_compare : KeyCompare {
    constexpr bool operator()(const std::pair<Key, Value>& a,
                              const std::pair<Key, Value>& b) const {
        return KeyCompare::operator()(std::get<0>(a), std::get<0>(b));
    }
    constexpr bool operator()(const Key& a,
                              const std::pair<Key, Value>& b) const {
        return KeyCompare::operator()(a, std::get<0>(b));
    }
    constexpr bool operator()(const std::pair<Key, Value>& a,
                              const Key& b) const {
        return KeyCompare::operator()(std::get<0>(a), b);
    }
};
}  // namespace d_ary

template <std::size_t D, typename RandomIt, typename Compare>
void make_heap(RandomIt begin, RandomIt end, Compare comp) {
    const std::size_t n = std::distance(begin, end);
    for (std::size_t i = 0; i < n; ++i) {
        d_ary::sift_up<D>(begin, i, comp);
    }
}
template <std::size_t D, typename RandomIt, typename Compare>
void heap_pop(RandomIt begin, RandomIt end, Compare comp) {
    RandomIt tail = end - 1;
    std::swap(*begin, *tail);
    d_ary::sift_down<D>(begin, tail, 0, comp);
}
template <std::size_t D, typename RandomIt, typename Compare>
void heap_push(RandomIt begin, RandomIt end, Compare comp) {
    d_ary::sift_up<D>(begin, std::distance(begin, end) - 1, comp);
}

template <std::size_t D, typename Key, typename Value,
          typename KeyCompare = std::less<Key>>
class dary_heap
    : protected d_ary::key_compare_to_value_compare<Key, Value, KeyCompare> {
  public:
    using key_type = Key;
    using mapped_type = Value;
    using value_type = std::pair<key_type, mapped_type>;
    using container_type = std::vector<value_type>;
    using iterator = typename container_type::iterator;
    using const_iterator = typename container_type::const_iterator;
    using key_compare = KeyCompare;
    using value_compare =
        d_ary::key_compare_to_value_compare<Key, Value, key_compare>;
    using reference = typename container_type::reference;
    using const_reference = typename container_type::const_reference;

  private:
    container_type __M_c;

  public:
    constexpr const value_compare& compare() const noexcept(true) {
        return static_cast<const value_compare&>(*this);
    }
    constexpr const key_compare& key_comp() const noexcept(true) {
        return static_cast<const key_compare&>(*this);
    }

    constexpr iterator begin() noexcept(true) { return __M_c.begin(); }
    constexpr iterator end() noexcept(true) { return __M_c.end(); }
    constexpr const_iterator begin() const noexcept(true) {
        return __M_c.begin();
    }
    constexpr const_iterator end() const noexcept(true) { return __M_c.end(); }

    void insert(value_type&& v) {
        __M_c.push_back(std::move(v));
        heap_push<D>(begin(), end(), compare());
    }
    void insert(const value_type&& v) {
        __M_c.push_back(v);
        heap_push<D>(begin(), end(), compare());
    }
    template <typename K> void insert(K&& k) {
        __M_c.push_back(std::forward<K>(k));
        heap_push<D>(begin(), end(), compare());
    }
    template <typename... Args> void emplace(Args&&... args) {
        __M_c.emplace_back(std::forward<Args>(args)...);
        heap_push<D>(begin(), end(), compare());
    }
    void pop() {
        heap_pop<D>(begin(), end(), compare());
        __M_c.pop_back();
    }

    constexpr reference top() noexcept(true) { return __M_c.front(); }
    constexpr const_reference top() const noexcept(true) {
        return __M_c.front();
    }

    template <typename Fn> constexpr iterator find(Fn&& fn) noexcept(true) {
        return std::find_if(begin(), end(), std::forward<Fn>(fn));
    }

    template <typename T> void update(iterator pos, T&& t) {
        const std::size_t idx = std::distance(begin(), pos);
        value_type& old = *pos;
        if (compare()(old, std::forward<T>(t))) {
            old = std::forward<T>(t);
            d_ary::sift_down<D>(begin(), end(), idx, compare());
        } else {
            old = std::forward<T>(t);
            d_ary::sift_up<D>(begin(), idx, compare());
        }
    }
    void erase(iterator pos) {
        auto tail = end() - 1;
        std::swap(*pos, *tail);
        d_ary::sift_down<D>(begin(), tail, std::distance(begin(), pos),
                            compare());
        __M_c.pop_back();
    }

    constexpr std::size_t size() const noexcept(true) { return __M_c.size(); }
    constexpr bool empty() const noexcept(true) { return __M_c.empty(); }

    constexpr container_type& container() noexcept(true) { return __M_c; }
};
}  // namespace chx::net::detail
