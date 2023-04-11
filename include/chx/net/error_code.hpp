#pragma once

#include <cstring>
#include <system_error>

#include "./exception.hpp"

namespace chx::net {
struct errc {
    enum errc_impl : int {
        address_family_not_supported = EAFNOSUPPORT,
        address_in_use = EADDRINUSE,
        address_not_available = EADDRNOTAVAIL,
        already_connected = EISCONN,
        argument_list_too_long = E2BIG,
        argument_out_of_domain = EDOM,
        bad_address = EFAULT,
        bad_file_descriptor = EBADF,
        bad_message = EBADMSG,
        broken_pipe = EPIPE,
        connection_aborted = ECONNABORTED,
        connection_already_in_progress = EALREADY,
        connection_refused = ECONNREFUSED,
        connection_reset = ECONNRESET,
        cross_device_link = EXDEV,
        destination_address_required = EDESTADDRREQ,
        device_or_resource_busy = EBUSY,
        directory_not_empty = ENOTEMPTY,
        executable_format_error = ENOEXEC,
        file_exists = EEXIST,
        file_too_large = EFBIG,
        filename_too_long = ENAMETOOLONG,
        function_not_supported = ENOSYS,
        host_unreachable = EHOSTUNREACH,
        identifier_removed = EIDRM,
        illegal_byte_sequence = EILSEQ,
        inappropriate_io_control_operation = ENOTTY,
        interrupted = EINTR,
        invalid_argument = EINVAL,
        invalid_seek = ESPIPE,
        io_error = EIO,
        is_a_directory = EISDIR,
        message_size = EMSGSIZE,
        network_down = ENETDOWN,
        network_reset = ENETRESET,
        network_unreachable = ENETUNREACH,
        no_buffer_space = ENOBUFS,
        no_child_process = ECHILD,
        no_link = ENOLINK,
        no_lock_available = ENOLCK,
#ifdef ENODATA
        no_message_available = ENODATA,
#else
        no_message_available = ENOMSG,
#endif
        no_message = ENOMSG,
        no_protocol_option = ENOPROTOOPT,
        no_space_on_device = ENOSPC,
#ifdef ENOSR
        no_stream_resources = ENOSR,
#else
        no_stream_resources = ENOMEM,
#endif
        no_such_device_or_address = ENXIO,
        no_such_device = ENODEV,
        no_such_file_or_directory = ENOENT,
        no_such_process = ESRCH,
        not_a_directory = ENOTDIR,
        not_a_socket = ENOTSOCK,
#ifdef ENOSTR
        not_a_stream = ENOSTR,
#else
        not_a_stream = EINVAL,
#endif
        not_connected = ENOTCONN,
        not_enough_memory = ENOMEM,
        not_supported = ENOTSUP,
        operation_canceled = ECANCELED,
        operation_in_progress = EINPROGRESS,
        operation_not_permitted = EPERM,

        owner_dead = EOWNERDEAD,
        permission_denied = EACCES,
        protocol_error = EPROTO,
        protocol_not_supported = EPROTONOSUPPORT,
        read_only_file_system = EROFS,
        resource_deadlock_would_occur = EDEADLK,
        resource_unavailable_try_again = EAGAIN,
        result_out_of_range = ERANGE,
        state_not_recoverable = ENOTRECOVERABLE,
#ifdef ETIME
        stream_timeout = ETIME,
#else
        stream_timeout = ETIMEDOUT,
#endif
        text_file_busy = ETXTBSY,
        timed_out = ETIMEDOUT,
        too_many_files_open_in_system = ENFILE,
        too_many_files_open = EMFILE,
        too_many_links = EMLINK,
        too_many_symbolic_link_levels = ELOOP,
        value_too_large = EOVERFLOW,
        wrong_protocol_type = EPROTOTYPE,

        internal_error = 150,
        socket_already_open = 151,
        eof = 152
    };
};

namespace detail {
struct guarantee_errc_unique : net::errc {
    template <int> struct guarantee_errc_unique_impl {};
    template <int... Is>
    struct guarantee_errc_unique_helper : guarantee_errc_unique_impl<Is>... {};

    guarantee_errc_unique_helper<
        address_family_not_supported, address_in_use, address_not_available,
        already_connected, argument_list_too_long, argument_out_of_domain,
        bad_address, bad_file_descriptor, bad_message, broken_pipe,
        connection_aborted, connection_already_in_progress, connection_refused,
        connection_reset, cross_device_link, destination_address_required,
        device_or_resource_busy, directory_not_empty, executable_format_error,
        file_exists, file_too_large, filename_too_long, function_not_supported,
        host_unreachable, identifier_removed, illegal_byte_sequence,
        inappropriate_io_control_operation, interrupted, invalid_argument,
        invalid_seek, io_error, is_a_directory, message_size, network_down,
        network_reset, network_unreachable, no_buffer_space, no_child_process,
        no_link, no_lock_available, no_message_available, no_message,
        no_protocol_option, no_space_on_device, no_stream_resources,
        no_such_device_or_address, no_such_device, no_such_file_or_directory,
        no_such_process, not_a_directory, not_a_socket, not_a_stream,
        not_connected, not_enough_memory, not_supported, operation_canceled,
        operation_in_progress, operation_not_permitted, owner_dead,
        permission_denied, protocol_error, protocol_not_supported,
        read_only_file_system, resource_deadlock_would_occur,
        resource_unavailable_try_again, result_out_of_range,
        state_not_recoverable, stream_timeout, text_file_busy, timed_out,
        too_many_files_open_in_system, too_many_files_open, too_many_links,
        too_many_symbolic_link_levels, value_too_large, wrong_protocol_type,

        internal_error, socket_already_open, eof>
        v;
};
}  // namespace detail
}  // namespace chx::net

namespace std {
template <>
struct is_error_condition_enum<::chx::net::errc::errc_impl> : std::true_type {};
}  // namespace std

namespace chx::net {
inline std::error_category& error_category() {
    class __category : public std::error_category {
      public:
        virtual const char* name() const noexcept(true) override {
            return "chxnet error_category";
        }

        virtual std::error_condition default_error_condition(int ev) const
            noexcept(true) override {
            return std::error_condition(ev, net::error_category());
        }

        virtual bool equivalent(const std::error_code& ec, int ev) const
            noexcept(true) override {
            return *this == ec.category() && static_cast<int>(ec.value()) == ev;
        }

        virtual std::string message(int ev) const override {
            switch (ev) {
                case errc::internal_error: {
                    return "chxnet internal error";
                }
                case errc::socket_already_open: {
                    return "Socket already opened";
                }
                case errc::eof: {
                    return "Encountered EOF";
                }
                default: {
                    return ::strerror(ev);
                }
            }
        }
    } static __c;

    return __c;
}

inline std::error_condition make_error_condition(errc::errc_impl e) {
    return {e, error_category()};
}

namespace detail {
inline std::error_code make_ec(int code, const std::error_category& category =
                                             error_category()) noexcept(true) {
    return {code, category};
}
inline void assign_ec(
    std::error_code& ec, int code,
    const std::error_category& category = error_category()) noexcept(true) {
    ec.assign(code, category);
}

#define __CHXNET_MAKE_QUOTE_IMPL(s) #s
#define __CHXNET_MAKE_QUOTE(s) __CHXNET_MAKE_QUOTE_IMPL(s)

#define __CHXNET_MAKE_EX(ec)                    \
    ::chx::net::exception(ec.message() +        \
                          " at file: " __FILE__ \
                          " line: " __CHXNET_MAKE_QUOTE(__LINE__))
#define __CHXNET_MAKE_EX_WITH(ec, type)                   \
    ::chx::net::type(ec.message() + " at file: " __FILE__ \
                                    " line: " __CHXNET_MAKE_QUOTE(__LINE__))

#define __CHXNET_THROW(code)                                                  \
    throw ::chx::net::exception(::chx::net::detail::make_ec(code).message() + \
                                " at file: " __FILE__                         \
                                " line: " __CHXNET_MAKE_QUOTE(__LINE__))
#define __CHXNET_THROW_WITH(code, type)                                  \
    throw ::chx::net::type(::chx::net::detail::make_ec(code).message() + \
                           " at file: " __FILE__                         \
                           " line: " __CHXNET_MAKE_QUOTE(__LINE__))
#define __CHXNET_THROW_EC(ec) throw __CHXNET_MAKE_EX(ec)
#define __CHXNET_THROW_EC_WITH(ec, type) throw __CHXNET_MAKE_EX_WITH(ec, type)
}  // namespace detail
}  // namespace chx::net
