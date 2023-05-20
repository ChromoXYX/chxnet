#pragma once

#include <string_view>

namespace chx::net {
/**
 * @brief Scalable and continuous buffer.
 *
 * @tparam Container Underlying scalable container.
 */
template <typename Container> class dynamic_buffer {
    static_assert(sizeof(typename Container::value_type) ==
                  sizeof(unsigned char));

    Container& __M_container;
    unsigned char* __M_avail = nullptr;
    std::size_t __M_avail_sz = 0;
    const std::size_t __M_max_sz;

  public:
    using value_type = unsigned char;

    /**
     * @brief Construct a new dynamic_buffer object from a container.
     *
     * @param container Underlying scalable container.
     */
    explicit dynamic_buffer(Container& container) noexcept(true)
        : __M_container(container), __M_max_sz(container.max_size()) {}
    /**
     * @brief Construct a new dynamic_buffer object from a container, with
     * specified max size.
     *
     * @param container Underlying scalable container.
     * @param max_size Max size of the dynamic_buffer.
     */
    explicit dynamic_buffer(Container& container,
                            std::size_t max_size) noexcept(true)
        : __M_container(container), __M_max_sz(max_size) {}

    dynamic_buffer(const dynamic_buffer&) = default;
    dynamic_buffer(dynamic_buffer&&) = default;

    /**
     * @brief Get underlying container.
     *
     * @return constexpr Container&
     */
    constexpr Container& underlying_container() const noexcept(true) {
        return __M_container;
    }
    /**
     * @brief Get a pointer to the first available character in the buffer.
     *
     * @return constexpr value_type*
     */
    constexpr value_type* data() const noexcept(true) { return __M_avail; }
    /**
     * @brief Get available size of the buffer.
     *
     * @return constexpr std::size_t
     */
    constexpr std::size_t size() const noexcept(true) { return __M_avail_sz; }
    /**
     * @brief Get max size.
     *
     * @return constexpr std::size_t
     */
    constexpr std::size_t max_size() const noexcept(true) { return __M_max_sz; }

#define __CHXNET_TO_UC_PTR(ptr)                                                \
    static_cast<unsigned char*>(static_cast<void*>(ptr))

    /**
     * @brief Construct a view of consumed data.
     *
     * @return constexpr std::basic_string_view<unsigned char>
     */
    constexpr std::basic_string_view<unsigned char> view() noexcept(true) {
        if (__M_avail) {
            return {__CHXNET_TO_UC_PTR(__M_container.data()),
                    __M_container.size() - __M_avail_sz};
        } else {
            return {};
        }
    }

    /**
     * @brief Extend the buffer.
     *
     * @details Extend the buffer to the new available size. When size is
     * smaller than available size, nothing will happen.
     *
     * @param size New available size.
     */
    void extend(std::size_t size) {
        if (size > __M_avail_sz) {
            size -= __M_avail_sz;
            if (size + __M_container.size() <= __M_max_sz) {
                std::size_t avail_pos = __M_container.size() - __M_avail_sz;
                __M_container.resize(__M_container.size() + size);
                __M_avail =
                    __CHXNET_TO_UC_PTR(__M_container.data()) + avail_pos;
                __M_avail_sz = __M_container.size() - avail_pos;
            } else {
                extend(__M_max_sz - __M_container.size());
            }
        }
    }
    /**
     * @brief Notify the buffer that size bytes are consumed.
     *
     * @param size Size of bytes which are consumed.
     */
    constexpr void consume(std::size_t size) noexcept(true) {
        if (__M_avail) {
            __M_avail_sz -= size;
            __M_avail += size;
        }
    }
    /**
     * @brief Remove the available part of the buffer.
     *
     */
    void shrink() {
        if (__M_avail) {
            std::size_t avail_pos = __M_container.size() - __M_avail_sz;
            __M_container.resize(avail_pos);
            __M_avail = nullptr;
            __M_avail_sz = 0;
        }
    }
#undef __CHXNET_TO_UC_PTR
};
}  // namespace chx::net
