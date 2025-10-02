AC_INIT([chxnet], [0.0], [])
AM_INIT_AUTOMAKE([-Werror -Wall foreign])

AC_SUBST([CHXNET_VERSION], ["0.0"])

AC_PROG_CXX
AC_LANG([C++])

AC_MSG_CHECKING([kernel version])
CHXNET_KERNEL_VERSION=$(uname -r | cut -d "." -f 1,2)
CHXNET_KERNEL_VERSION_MAJOR=$(echo $CHXNET_KERNEL_VERSION | cut -d "." -f 1)
CHXNET_KERNEL_VERSION_MINOR=$(echo $CHXNET_KERNEL_VERSION | cut -d "." -f 2)
AC_MSG_RESULT([$CHXNET_KERNEL_VERSION])

AC_SUBST([CHXNET_KERNEL_VERSION])
AC_SUBST([CHXNET_KERNEL_VERSION_MAJOR])
AC_SUBST([CHXNET_KERNEL_VERSION_MINOR])

CHXNET_TEST_CXXFLAGS="-DCHXNET_KERNEL_VERSION_MAJOR=$CHXNET_KERNEL_VERSION_MAJOR -DCHXNET_KERNEL_VERSION_MINOR=$CHXNET_KERNEL_VERSION_MINOR -I../include"

CHXNET_TEST_CXXFLAGS_CXX17="$CHXNET_TEST_CXXFLAGS -std=c++17"
CHXNET_TEST_CXXFLAGS_CXX20="$CHXNET_TEST_CXXFLAGS -std=c++20"

CHXNET_TEST_LDADD="-lssl -lcrypto"

AC_SUBST([CHXNET_TEST_CXXFLAGS])
AC_SUBST([CHXNET_TEST_CXXFLAGS_CXX17])
AC_SUBST([CHXNET_TEST_CXXFLAGS_CXX20])
AC_SUBST([CHXNET_TEST_LDADD])

AC_ARG_WITH([liburing],
    [AS_HELP_STRING([--with-liburing=DIR],
        [use liburing located in DIR])],
    [
        AC_MSG_CHECKING([for liburing.h in $withval/include])
        AS_IF([test -f "$withval/include/liburing.h"],
            [
                AC_MSG_RESULT([yes])
                CHXNET_TEST_CXXFLAGS="$CHXNET_TEST_CXXFLAGS -I$withval/include"
                CHXNET_TEST_CXXFLAGS_CXX17="$CHXNET_TEST_CXXFLAGS_CXX17 -I$withval/include"
                CHXNET_TEST_CXXFLAGS_CXX20="$CHXNET_TEST_CXXFLAGS_CXX20 -I$withval/include"
                
                AC_MSG_CHECKING([for liburing.a in $withval/lib])
                AS_IF([test -f "$withval/lib/liburing.a"],
                    [
                        AC_MSG_RESULT([yes])
                        CHXNET_TEST_LDADD="$CHXNET_TEST_LDADD $withval/lib/liburing.a"
                    ],
                    [
                        AC_MSG_RESULT([no])
                        AC_MSG_ERROR([cannot find liburing.a in $withval/lib])
                    ])
            ],
            [
                AC_MSG_RESULT([no])
                AC_MSG_ERROR([cannot find liburing.h in $withval/include])
            ])
    ],
    [
        AC_CHECK_HEADER([liburing.h], [],
            [AC_MSG_ERROR([cannot find liburing.h in system include directories])])
        
        AC_CHECK_LIB([uring], [io_uring_queue_init],
            [CHXNET_TEST_LDADD="$CHXNET_TEST_LDADD -luring"],
            [AC_MSG_ERROR([cannot link against liburing])])
    ])

AC_SUBST([CHXNET_TEST_CXXFLAGS])
AC_SUBST([CHXNET_TEST_CXXFLAGS_CXX17])
AC_SUBST([CHXNET_TEST_CXXFLAGS_CXX20])
AC_SUBST([CHXNET_TEST_LDADD])

AC_CONFIG_FILES([
    Makefile
    include/Makefile
    test/Makefile
    pkgconfig/Makefile
    pkgconfig/chxnet.pc
])

AC_OUTPUT
