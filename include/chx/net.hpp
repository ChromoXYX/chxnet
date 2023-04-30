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
#include "./net/dynamic_buffer.hpp"
#include "./net/io_context.hpp"
#include "./net/ip.hpp"
#include "./net/signal.hpp"
#include "./net/tcp.hpp"
#include "./net/udp.hpp"
#include "./net/ktimer.hpp"
