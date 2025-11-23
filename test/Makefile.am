LDADD = @CHXNET_TEST_LDADD@
check_PROGRAMS = \
    io_uring_acquire \
    proxy \
    async_recvmsg
TESTS = \
    io_uring_acquire \
    proxy \
    async_recvmsg

io_uring_acquire_SOURCES = io_uring_acquire.cpp
io_uring_acquire_CXXFLAGS = @CHXNET_TEST_CXXFLAGS_CXX20@

proxy_SOURCES = proxy.cpp
proxy_CXXFLAGS = @CHXNET_TEST_CXXFLAGS_CXX20@

async_recvmsg_SOURCES = async_recvmsg.cpp
async_recvmsg_CXXFLAGS = @CHXNET_TEST_CXXFLAGS_CXX20@

LOG_COMPILER = valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1
