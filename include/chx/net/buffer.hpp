#pragma once

#include <bits/types/struct_iovec.h>
#include <cstddef>
#include <type_traits>
#include <utility>

namespace chx::net {
namespace detail {
struct has_data_and_size_impl {
    template <typename T, typename = decltype(std::declval<T>().data()),
              typename = decltype(std::declval<T>().size())>
    has_data_and_size_impl(T) {}
};
struct has_data_impl {
    template <typename T, typename = decltype(std::declval<T>().data())>
    has_data_impl(T) {}
};
template <typename T>
using is_const_data =
    std::is_const<std::remove_pointer_t<decltype(std::declval<T>().data())>>;
}  // namespace detail

/**
 * @brief Mutable contiguous buffer, which contains the start location and size
 * to a piece of memory.
 *
 */
class mutable_buffer {
    void* __M_data = nullptr;
    std::size_t __M_sz = 0;

  public:
    constexpr mutable_buffer() noexcept(true) = default;
    constexpr mutable_buffer(const mutable_buffer&) noexcept(true) = default;

    constexpr void* const data() const noexcept(true) { return __M_data; }
    constexpr std::size_t size() const noexcept(true) { return __M_sz; }

    template <typename T, std::size_t Size,
              typename = std::enable_if_t<!std::is_const<T>::value>>
    explicit constexpr mutable_buffer(T (&b)[Size]) noexcept(true)
        : __M_data(b), __M_sz(Size * sizeof(T)) {}
    template <typename T, std::size_t Size,
              typename = std::enable_if_t<!std::is_const<T>::value>>
    explicit constexpr mutable_buffer(T (&b)[Size],
                                      std::size_t size) noexcept(true)
        : __M_data(b), __M_sz(size) {}

    explicit constexpr mutable_buffer(struct iovec& io) noexcept(true)
        : __M_data(io.iov_base), __M_sz(io.iov_len) {}

    template <
        typename Container,
        typename = std::enable_if_t<
            std::is_constructible_v<detail::has_data_and_size_impl, Container>>,
        typename = std::enable_if_t<!std::is_const<Container>::value>,
        typename = std::enable_if_t<!detail::is_const_data<Container>::value>>
    explicit mutable_buffer(Container& b) noexcept(true)
        : __M_data(b.data()),
          __M_sz(b.size() * sizeof(typename Container::value_type)) {}
    template <
        typename Container,
        typename = std::enable_if_t<
            std::is_constructible_v<detail::has_data_impl, Container>>,
        typename = std::enable_if_t<!std::is_const<Container>::value>,
        typename = std::enable_if_t<!detail::is_const_data<Container>::value>>
    explicit mutable_buffer(Container& b, std::size_t size) noexcept(true)
        : __M_data(b.data()), __M_sz(size) {}

    template <typename T, typename = std::enable_if_t<!std::is_const<T>::value>>
    explicit constexpr mutable_buffer(T* b, std::size_t size) noexcept(true)
        : __M_data(b), __M_sz(size) {}
};

/**
 * @brief Cont contiguous buffer, which contains the start location and size
 * to a piece of memory.
 *
 */
class const_buffer {
    const void* __M_data = nullptr;
    std::size_t __M_sz = 0;

  public:
    constexpr const_buffer() = default;
    constexpr const_buffer(const const_buffer&) noexcept(true) = default;

    constexpr const_buffer(const mutable_buffer& b) noexcept(true)
        : __M_data(b.data()), __M_sz(b.size()) {}

    constexpr const void* const data() const noexcept(true) { return __M_data; }
    constexpr std::size_t size() const noexcept(true) { return __M_sz; }

    template <typename T, std::size_t Size>
    explicit constexpr const_buffer(const T (&b)[Size]) noexcept(true)
        : __M_data(b), __M_sz(Size * sizeof(T)) {}
    template <typename T, std::size_t Size>
    explicit constexpr const_buffer(const T (&b)[Size],
                                    std::size_t size) noexcept(true)
        : __M_data(b), __M_sz(size) {}

    explicit constexpr const_buffer(const struct iovec& io) noexcept(true)
        : __M_data(io.iov_base), __M_sz(io.iov_len) {}

    template <typename Container,
              typename = std::enable_if_t<std::is_constructible_v<
                  detail::has_data_and_size_impl, Container>>>
    explicit const_buffer(const Container& b) noexcept(true)
        : __M_data(b.data()),
          __M_sz(b.size() * sizeof(typename Container::value_type)) {}
    template <typename Container,
              typename = std::enable_if_t<
                  std::is_constructible_v<detail::has_data_impl, Container>>>
    explicit const_buffer(const Container& b, std::size_t size) noexcept(true)
        : __M_data(b.data()), __M_sz(size) {}

    template <typename T>
    explicit constexpr const_buffer(const T* b, std::size_t size) noexcept(true)
        : __M_data(b), __M_sz(size) {}
};

/**
 * @brief Make a buffer from given object.
 *
 * @tparam Obj
 * @param obj
 * @return auto mutable_buffer if a mutable_buffer is constructible with obj,
 * otherwise const_buffer.
 */
template <typename Obj> auto buffer(Obj&& obj) noexcept(true) {
    if constexpr (std::is_constructible_v<mutable_buffer, decltype(obj)>) {
        return mutable_buffer(std::forward<Obj>(obj));
    } else {
        return const_buffer(std::forward<Obj>(obj));
    }
}
/**
 * @brief Make a buffer from given object, with a specific size.
 *
 * @tparam Obj
 * @param obj
 * @param size Size of the piece of contiguous memory in byte.
 * @return auto mutable_buffer if a mutable_buffer is constructible with obj,
 * otherwise const_buffer.
 */
template <typename Obj>
auto buffer(Obj&& obj, std::size_t size) noexcept(true) {
    if constexpr (std::is_constructible_v<mutable_buffer, decltype(obj),
                                          std::size_t>) {
        return mutable_buffer(std::forward<Obj>(obj), size);
    } else {
        return const_buffer(std::forward<Obj>(obj), size);
    }
}

template <typename T>
using is_buffer =
    std::integral_constant<bool,
                           std::is_constructible_v<const_buffer, T> ||
                               std::is_constructible_v<mutable_buffer, T>>;

namespace detail {
template <typename Buffer>
using is_const_buffer = std::is_convertible<Buffer, const_buffer>;
template <typename Buffer>
using is_mutable_buffer = std::is_convertible<Buffer, mutable_buffer>;
}  // namespace detail
}  // namespace chx::net
