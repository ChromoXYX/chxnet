#pragma once

#include "../resolver.hpp"
#include "../../cancellation.hpp"
#include "../../detail/atomic.hpp"
#include "../../detail/task_carrier.hpp"
#include <netdb.h>

namespace chx::net {
namespace detail {
namespace tags {
struct resolver {};
}  // namespace tags

template <> struct async_operation<tags::resolver> {
    struct query_type {
        std::string hostname;
        atomic<bool> is_cancelled = {false};

        struct {
            int ret = 0;
            ip::addrinfo_list addr;
        } result;
    };

    static void interrupt(io_uring* from, task_decl* task) {
        io_uring_sqe* sqe = io_uring_get_sqe(from);
        if (!sqe) {
            io_uring_submit(from);
            sqe = io_uring_get_sqe(from);
        }
        if (!sqe) {
            __CHXNET_THROW_CSTR("Failed to get sqe");
        }
        io_uring_prep_msg_ring(
            sqe, task->get_associated_io_context().native_handler(), 0,
            (std::uint64_t)task, 0);
    }
    static void step(io_uring* ring) {
        io_uring_submit(ring);
        unsigned head;
        io_uring_cqe* cqe;
        unsigned nr = 0;
        io_uring_for_each_cqe(ring, head, cqe) { ++nr; }
        io_uring_cq_advance(ring, nr);
    }
    static void worker(ip::resolver* self) {
        io_uring ring;
        assert(!io_uring_queue_init(4096, &ring, 0));
        scope_exit g([&]() { io_uring_queue_exit(&ring); });
        for (; !self->__M_stop.load(std::memory_order_acquire);) {
            task_decl* task = self->__M_ch.acquire();
            if (!task) {
                continue;
            }
            self->__M_posted.fetch_sub(1, std::memory_order_relaxed);
            query_type* query =
                static_cast<query_type*>(task->__M_additional_ptr);
            if (!query->is_cancelled.load(std::memory_order_relaxed)) {
                addrinfo* addr = nullptr;
                int ret = ::getaddrinfo(query->hostname.c_str(), nullptr,
                                        nullptr, &addr);
                query->result.ret = ret;
                query->result.addr = ip::addrinfo_list(addr);
            } else {
                query->result.ret = ECANCELED;
                query->result.addr = {};
            }
            interrupt(&ring, task);
            step(&ring);
        }
    }

    template <typename BindCompletionToken>
    decltype(auto) operator()(ip::resolver* self,
                              BindCompletionToken&& bind_completion_token) {
        task_decl* task = self->__M_ctx->acquire();
        return async_token_init(
            task->__M_token.emplace(async_token_generate(
                task,
                [](auto& token, task_decl* self) -> int {
                    query_type* q =
                        static_cast<query_type*>(self->__M_additional_ptr);
                    token(make_ec(q->result.ret), std::move(q->result.addr));
                    return 0;
                },
                bind_completion_token)),
            bind_completion_token);
    }

    void cancel_all(ip::resolver* self) {
        self->stop();
        self->join();
        std::size_t n = self->__M_posted.load(std::memory_order_relaxed);
        std::size_t i = 0;
        while (i < n) {
            task_decl* task = self->__M_ch.acquire();
            if (!task) {
                continue;
            }
            ++i;
            query_type* q = static_cast<query_type*>(task->__M_additional_ptr);
            q->result.ret = ECANCELED;
            q->result.addr = {};
            io_uring_prep_nop(self->__M_ctx->get_sqe(task));
        }
    }
};
}  // namespace detail

inline ip::resolver::resolver(io_context& ctx, std::size_t n)
    : __M_ctx(&ctx), __M_ch(ctx) {
    for (std::size_t i = 0; i < n; ++i) {
        __M_pool.emplace_back(
            &net::detail::async_operation<net::detail::tags::resolver>::worker,
            this);
    }
}

template <typename CompletionToken>
decltype(auto) ip::resolver::async_resolve(std::string hostname,
                                           CompletionToken&& completion_token) {
    using impl = net::detail::async_operation<net::detail::tags::resolver>;
    impl::query_type q;
    q.hostname = std::move(hostname);
    return impl()(
        this,
        net::detail::task_carrier_s2(
            net::detail::async_token_bind<const std::error_code&,
                                          addrinfo_list>(
                std::forward<CompletionToken>(completion_token)),
            std::move(q),
            [this](task_decl* task, auto ti, impl::query_type* q) {
                task->__M_additional_ptr = q;
                struct cancel_impl {
                    void operator()(task_decl* self) const {
                        auto* q = static_cast<net::detail::async_operation<
                            net::detail::tags::resolver>::query_type*>(
                            self->__M_additional_ptr);
                        q->is_cancelled.store(true, std::memory_order_relaxed);
                    }
                };
                task->__M_custom_cancellation =
                    static_cancellation_controller<cancel_impl>();

                __M_ch.post(task);
                __M_posted.fetch_add(1, std::memory_order_relaxed);
            }));
}

inline void ip::resolver::cancel() {
    net::detail::async_operation<net::detail::tags::resolver>().cancel_all(
        this);
}
}  // namespace chx::net
