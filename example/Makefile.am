AM_CXXFLAGS = @__CHXNET_EXEC_CXXFLAGS@ -I../include
bin_PROGRAMS = chxnet_echo chxnet_udp chxnet_ktimer \
    chxnet_coro chxnet_tls_server \
    chxnet_sendfile chxnet_timer chxnet_semaphore

if CHXNET_WITH_LLHTTP
bin_PROGRAMS += chxnet_http
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
chxnet_timer_SOURCES = timer.cpp
chxnet_timer_LDADD = @__CHXNET_EXEC_LDADD@
chxnet_semaphore_SOURCES = semaphore.cpp
chxnet_semaphore_LDADD = @__CHXNET_EXEC_LDADD@
