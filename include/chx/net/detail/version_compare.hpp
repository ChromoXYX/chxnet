#pragma once

#define CHXNET_KERNEL_VERSION_LESS(major, minor)                               \
    ((major > CHXNET_KERNEL_VERSION_MAJOR) ||                                  \
     (major == CHXNET_KERNEL_VERSION_MAJOR &&                                  \
      minor > CHXNET_KERNEL_VERSION_MINOR))

#define CHXNET_KERNEL_VERSION_EQUAL(major, minor)                              \
    ((major == CHXNET_KERNEL_VERSION_MAJOR &&                                  \
      minor == CHXNET_KERNEL_VERSION_MINOR))

#define CHXNET_KERNEL_VERSION_GREATER(major, minor)                            \
    ((major < CHXNET_KERNEL_VERSION_MAJOR) ||                                  \
     (major == CHXNET_KERNEL_VERSION_MAJOR &&                                  \
      minor < CHXNET_KERNEL_VERSION_MINOR))
