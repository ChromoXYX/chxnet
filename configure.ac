AC_INIT([0.0], [chxnet examples])
AM_INIT_AUTOMAKE([-Werror -Wall foreign])

AC_SUBST(__CHXNET_VERSION, ["0.0"])

AC_SUBST(__CHXNET_TEST_LDADD, ["-lssl -lcrypto"])
AC_SUBST(__CHXNET_TEST_CXXFLAGS)

AC_SUBST(__CHXNET_KERNEL_VERSION, [$(echo `uname -r` | cut -d "." -f 1,2)])
AC_SUBST(__CHXNET_KERNEL_VERSION_MAJOR, [$(echo $__CHXNET_KERNEL_VERSION | cut -d "." -f 1)])
AC_SUBST(__CHXNET_KERNEL_VERSION_MINOR, [$(echo $__CHXNET_KERNEL_VERSION | cut -d "." -f 2)])
AC_SUBST(__CHXNET_TEST_CXXFLAGS, 
["$__CHXNET_TEST_CXXFLAGS -DCHXNET_KERNEL_VERSION_MAJOR=$__CHXNET_KERNEL_VERSION_MAJOR -DCHXNET_KERNEL_VERSION_MINOR=$__CHXNET_KERNEL_VERSION_MINOR"])

AC_ARG_WITH([liburing],
    AS_HELP_STRING([--with-liburing=<liburing-DIR>],
        [use liburing located in <liburing-DIR>]),
[
    AC_MSG_CHECKING([for include/liburing.h in $withval])
    AS_IF([test -f "$withval/include/liburing.h"], [
        AC_MSG_RESULT([yes])
        __CHXNET_TEST_CXXFLAGS="$__CHXNET_TEST_CXXFLAGS -I$withval/include"

        AC_MSG_CHECKING([for lib/liburing.a in $withval])
        AS_IF([test -f "$withval/lib/liburing.a"], [
            AC_MSG_RESULT([yes])
            __CHXNET_TEST_LDADD="$__CHXNET_TEST_LDADD $withval/lib/liburing.a"
        ], [
            AC_MSG_RESULT([no])
            AC_MSG_ERROR([cannot find lib/liburing.a in $withval])
        ])
    ], [
        AC_MSG_RESULT([no])
        AC_MSG_ERROR([cannot find include/liburing.h in $withval])
    ])
], [
    AC_CHECK_HEADER([liburing.h], [], [
        AC_MSG_ERROR([cannot find liburing.h in system include dirs])
    ])
    AC_CHECK_LIB([uring], [io_uring_queue_init], [
        __CHXNET_TEST_LDADD="$__CHXNET_TEST_LDADD -luring"
    ], [
        AC_MSG_ERROR([cannot link against liburing, -luring failed])
    ])
]
)

AC_PROG_CXX
dnl AX_CXX_COMPILE_STDCXX_17([noext], [mandatory])
AC_SUBST(CXXFLAGS, ["$CXXFLAGS -std=c++20"])
AC_CONFIG_FILES([
    Makefile
    pkgconfig/chxnet.pc

    include/Makefile
    test/Makefile
    pkgconfig/Makefile
])
AC_OUTPUT
