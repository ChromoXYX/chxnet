#pragma once

#include "../file.hpp"

namespace chx::net::detail {
namespace tags {
struct file_splice {};
struct file_sendfile {
    struct operation;
};
}  // namespace tags

template <> struct async_operation<tags::file_splice> {

};
}  // namespace chx::net::detail