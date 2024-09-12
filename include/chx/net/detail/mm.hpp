#pragma once

#include <cstdlib>
#include <unordered_map>
#include <utility>

#include "./noncopyable.hpp"

namespace chx::net::detail {
struct mm {
  private:
    struct blocks : CHXNET_NONCOPYABLE {
        struct block : CHXNET_NONCOPYABLE {
            blocks* parent = nullptr;
            block* next = nullptr;
            alignas(std::max_align_t) unsigned char buffer[];

            constexpr void* entry() noexcept(true) { return &buffer; }
        };

        blocks(std::size_t n, mm* p) : blsz(n), pm(p) {
            pm->clu.emplace(n, this);
        }
        ~blocks() noexcept(true) {
            while (bls) {
                ::free(std::exchange(bls, bls->next));
            }
        }

        block* bls = nullptr;
        const std::size_t blsz;
        std::size_t blc = 0;
        mm* const pm;

        void* acquire() {
            if (bls) {
                --blc;
                return std::exchange(bls, bls->next)->entry();
            } else {
                auto* p = static_cast<block*>(::malloc(sizeof(block) + blsz));
                p->parent = this;
                p->next = nullptr;
                return p->entry();
            }
        }
        constexpr void give_back(block* bl) noexcept(true) {
            if (bl) {
                if (pm->opt.max_bls_size_in_bytes == 0 ||
                    blc * blsz <= pm->opt.max_bls_size_in_bytes) {
                    ++blc;
                    bl->next = bls;
                    bls = bl;
                } else {
                    ::free(bl);
                }
            }
        }
    };
    friend struct blocks;
    struct __options {
        std::size_t mm_threshold = 0;
        std::size_t max_bls_size_in_bytes = 0;
    } opt = {};
    std::unordered_map<std::size_t, blocks*> clu;

  public:
    using options_type = __options;
    using blocks_type = blocks;
    using block_type = blocks::block;

    template <std::size_t N> void* allocate() {
        if (opt.mm_threshold == 0 || N <= opt.mm_threshold) {
            static thread_local blocks_type bls(N, this);
            return bls.acquire();
        } else {
            block_type* bl = new block_type;
            bl->parent = nullptr;
            bl->next = nullptr;
            return bl->entry();
        }
    }
    void deallocate(void* ptr) noexcept(true) {
        blocks::block* bl = (blocks::block*)((char*)ptr - 16);
        if (bl->parent) {
            bl->parent->give_back(bl);
        } else {
            ::free(bl);
        }
    }

    constexpr const options_type& get_options() const noexcept(true) {
        return opt;
    }
    constexpr options_type& get_options() noexcept(true) { return opt; }
    constexpr const auto& memory_view() const noexcept(true) { return clu; }
};
inline thread_local mm thread_mm = {};
}  // namespace chx::net::detail
