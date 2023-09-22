#pragma once

#if __cplusplus >= 202002L
#define CHXNET_ENABLE_COROUTINE 1
#endif

#include "./net/attribute.hpp"

#include "./net/error_code.hpp"
#include "./net/exception.hpp"

#include "./net/async_combine.hpp"
#include "./net/async_token.hpp"
#include "./net/as_tuple.hpp"
#include "./net/basic_socket.hpp"
#include "./net/buffer.hpp"
#include "./net/buffer_sequence.hpp"
#include "./net/cancellation.hpp"
#include "./net/coroutine2.hpp"
#include "./net/detached.hpp"
#include "./net/dynamic_buffer.hpp"
#include "./net/io_context.hpp"
#include "./net/ip.hpp"
#include "./net/signal.hpp"
#include "./net/tcp.hpp"
#include "./net/udp.hpp"
#include "./net/ktimer.hpp"
#include "./net/async_read_until.hpp"
#include "./net/async_read.hpp"
#include "./net/file_descriptor.hpp"
#include "./net/file.hpp"
#include "./net/async_sendfile.hpp"
#include "./net/managed.hpp"
#include "./net/async_write_sequence.hpp"
#include "./net/async_write_sequence_exactly.hpp"
#include "./net/async_read_sequence.hpp"
#include "./net/async_write_some_exactly.hpp"
#include "./net/async_openat.hpp"
#include "./net/utility.hpp"
