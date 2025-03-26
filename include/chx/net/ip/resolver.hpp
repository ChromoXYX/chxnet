#pragma once

#include "../io_context.hpp"
#include "../channel.hpp"
#include <netdb.h>
#include <thread>

namespace chx::net::ip {
class addrinfo_list {
    CHXNET_NONCOPYABLE;

  private:
    struct deleter {
        void operator()(addrinfo* p) const noexcept(true) { freeaddrinfo(p); }
    };

    std::unique_ptr<addrinfo, deleter> head_;

  public:
    class iterator {
      private:
        const addrinfo* ptr_;

      public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = addrinfo;
        using difference_type = std::ptrdiff_t;
        using pointer = const addrinfo*;
        using reference = const addrinfo&;

        constexpr explicit iterator(const addrinfo* p = nullptr) noexcept(true)
            : ptr_(p) {}

        constexpr iterator& operator++() noexcept(true) {
            if (ptr_)
                ptr_ = ptr_->ai_next;
            return *this;
        }

        constexpr iterator operator++(int) noexcept(true) {
            iterator tmp = *this;
            ++(*this);
            return tmp;
        }

        constexpr reference operator*() const noexcept(true) { return *ptr_; }
        constexpr pointer operator->() const noexcept(true) { return ptr_; }

        constexpr bool operator==(const iterator& other) const noexcept(true) {
            return ptr_ == other.ptr_;
        }

        constexpr bool operator!=(const iterator& other) const noexcept(true) {
            return !(*this == other);
        }
    };

    using reference = const addrinfo&;

    addrinfo_list() noexcept(true) = default;
    explicit addrinfo_list(addrinfo* p) noexcept(true) : head_(p) {}
    addrinfo_list(addrinfo_list&&) noexcept(true) = default;
    addrinfo_list& operator=(addrinfo_list&&) noexcept(true) = default;

    iterator begin() const noexcept(true) { return iterator(head_.get()); }
    iterator end() const noexcept(true) { return iterator(nullptr); }

    reference front() const noexcept(true) { return *begin(); }

    bool empty() const noexcept(true) { return !head_; }

    const addrinfo* get() const noexcept(true) { return head_.get(); }
    addrinfo* release() noexcept(true) { return head_.release(); }
};

class resolver {
    template <typename> friend struct net::detail::async_operation;
    CHXNET_NONCOPYABLE;
    CHXNET_NONMOVEABLE;

    io_context* const __M_ctx;
    channel __M_ch;

    alignas(64) std::atomic<bool> __M_stop = {false};
    alignas(64) std::atomic_uint64_t __M_posted = {0};

    std::vector<std::thread> __M_pool;

  public:
    resolver(io_context& ctx, std::size_t pool_n = 1);
    ~resolver() {
        if (std::any_of(__M_pool.begin(), __M_pool.end(),
                        [](const std::thread& th) { return th.joinable(); })) {
            std::terminate();
        }
    }

    template <typename CompletionToken>
    decltype(auto) async_resolve(std::string hostname,
                                 CompletionToken&& completion_token);
    void stop() {
        __M_stop.store(true, std::memory_order_acq_rel);
        const std::size_t n = __M_pool.size();
        for (std::size_t i = 0; i < n; ++i) {
            __M_ch.post(nullptr);
        }
        __M_ch.interrupt();
    }
    void join() {
        for (auto& th : __M_pool) {
            th.join();
        }
        __M_pool.clear();
    }
    void cancel();
};

class jresolver : public resolver {
  public:
    using resolver::resolver;
    ~jresolver() { cancel(); }
};
}  // namespace chx::net::ip

#include "./impl/resolver.ipp"
