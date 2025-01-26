#pragma once

#include "../io_context.hpp"
#include "../error_code.hpp"

namespace chx::net::detail {
inline std::error_code
get_ec(task_decl* t,
       const std::error_category& c = error_category()) noexcept(true) {
    auto* cqe = t->__M_cqe;
    return cqe->res >= 0 ? std::error_code{} : make_ec(-cqe->res, c);
}

inline constexpr int get_res(task_decl* t) noexcept(true) {
    return t->__M_cqe->res;
}
}  // namespace chx::net::detail
