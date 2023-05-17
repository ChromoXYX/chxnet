#pragma once

#include "./file_descriptor.hpp"

#include <filesystem>

namespace chx::net {
class file : public file_descriptor {
  public:
    using file_descriptor::file_descriptor;

    file(io_context& ctx, const char* filename, int flags = O_RDONLY,
         int mode = 0)
        : file_descriptor(ctx) {
        int fd = ::open(filename, flags, mode);
        if (fd > 0) {
            file_descriptor::set_fd(fd);
        } else {
            __CHXNET_THROW(errno);
        }
    }
    file(io_context& ctx, const std::string& str, int flags = O_RDONLY,
         int mode = 0)
        : file(ctx, str.c_str(), flags, mode) {}
    file(io_context& ctx, const std::filesystem::path& path,
         int flags = O_RDONLY, int mode = 0)
        : file(ctx, path.c_str(), flags, mode) {}
};
}  // namespace chx::net

#include "./impl/file.ipp"
