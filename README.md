# chxnet

An async network I/O library, imitates boost.asio, based on io_uring and liburing, for educational purpose. Now support basic tcp I/O and C++20 coroutine.

[TCP echo server with end-of-line marker](https://github.com/ChromoXYX/chxnet/blob/main/exec/echo.cpp)

[UDP example](https://github.com/ChromoXYX/chxnet/blob/main/exec/udp.cpp)

[Simple http server, which always responses with headers of requests](https://github.com/ChromoXYX/chxnet/blob/main/exec/http.cpp)

***Note:***

***Only gcc is supported, and the minimum version requirement is 12.1.***

***Full functionality requires a minimum kernel version 6.0. But most basic operations are available on older kernels.***

Functionalities or operations that require a kernel version higher than 5.15:

- Cancellation of an async object, 5.19. (If not satisfied, destructor of async objects cannot cancel async tasks associated with itself, leads to bad memory access. To avoid this, use a reference-counter such as shared_ptr.)

- UDP sendto, 6.0.

## Dependency

- [liburing](https://github.com/axboe/liburing)

## How to build

Run shell:

```shell
autoreconf -i -v
./configure
# ./configure --with-liburing=/path/to/liburing if liburing not in system default paths.
# See ./configure --help for details.
make
```

## Design

1. Task management layer (level-1, `io_context`)

    Level-1 provides async task allocation and life cycle management services for level-2.

2. Async Operation layer (level-2, `detail::async_operation`)

    All basic I/O operations are implemented in level-2, e.g. `async_read` and `async_write`.

3. Userland layer (level-3, I/O objects, `async_combine`)
  
    Level-3 provides abstraction and encapsulation based on level-2, such as `ip::tcp::socket`.

    Users could also combine multiple level-2 operation by `async_combine`.

## TODO

- Add udp support.
- Add kernel-free timer support.
- Add level-3 multithread support.
