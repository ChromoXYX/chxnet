AM_CXXFLAGS = @__CHXNET_EXEC_CXXFLAGS@ -I../include
noinst_PROGRAMS = chxnet_echo chxnet_udp chxnet_ktimer \
    chxnet_coro chxnet_tls_server \
    chxnet_sendfile chxnet_semaphore \
    chxnet_reusable_coro chxnet_multi \
    chxnet_poll chxnet_thread_executor \
    chxnet_resolver chxnet_zc

if CHXNET_WITH_LLHTTP
noinst_PROGRAMS += chxnet_http
chxnet_http_LDADD = @__CHXNET_EXEC_LDADD@
chxnet_http_SOURCES = http.cpp
endif

chxnet_echo_SOURCES = echo.cpp
chxnet_echo_LDADD = @__CHXNET_EXEC_LDADD@
chxnet_udp_SOURCES = udp.cpp
chxnet_udp_LDADD = @__CHXNET_EXEC_LDADD@
chxnet_ktimer_SOURCES = ktimer.cpp
chxnet_ktimer_LDADD = @__CHXNET_EXEC_LDADD@
chxnet_coro_SOURCES = coro.cpp
chxnet_coro_LDADD = @__CHXNET_EXEC_LDADD@
chxnet_tls_server_SOURCES = tls_server.cpp
chxnet_tls_server_LDADD = @__CHXNET_EXEC_LDADD@
chxnet_sendfile_SOURCES = sendfile.cpp
chxnet_sendfile_LDADD = @__CHXNET_EXEC_LDADD@
chxnet_semaphore_SOURCES = semaphore.cpp
chxnet_semaphore_LDADD = @__CHXNET_EXEC_LDADD@
chxnet_reusable_coro_SOURCES = reusable_coro.cpp
chxnet_reusable_coro_LDADD = @__CHXNET_EXEC_LDADD@
chxnet_multi_SOURCES = multi.cpp
chxnet_multi_LDADD = @__CHXNET_EXEC_LDADD@
chxnet_poll_SOURCES = poll.cpp
chxnet_poll_LDADD = @__CHXNET_EXEC_LDADD@
chxnet_thread_executor_SOURCES = thread_executor.cpp
chxnet_thread_executor_LDADD = @__CHXNET_EXEC_LDADD@
chxnet_resolver_SOURCES = resolver.cpp
chxnet_resolver_LDADD = @__CHXNET_EXEC_LDADD@
chxnet_zc_SOURCES = zc.cpp
chxnet_zc_LDADD = @__CHXNET_EXEC_LDADD@
