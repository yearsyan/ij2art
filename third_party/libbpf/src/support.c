// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Standalone ringbuf linkage: map-info syscall and stderr diagnostics only.
// Map-info implementation follows libbpf v1.7.0 src/bpf.c.
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "bpf.h"
#include "libbpf_internal.h"

int bpf_map_get_info_by_fd(int fd, struct bpf_map_info *info, __u32 *info_len)
{
    union bpf_attr attr;
    const size_t attr_sz = offsetofend(union bpf_attr, info);
    memset(&attr, 0, attr_sz);
    attr.info.bpf_fd = fd;
    attr.info.info_len = *info_len;
    attr.info.info = (uintptr_t)info;
    int err = syscall(__NR_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, attr_sz);
    if (!err)
        *info_len = attr.info.info_len;
    return libbpf_err_errno(err);
}

void libbpf_print(enum libbpf_print_level level, const char *format, ...)
{
    (void)level;
    int saved_errno = errno;
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    errno = saved_errno;
}

const char *libbpf_errstr(int err)
{
    // Thread-local storage avoids libc strerror() storage lifetime differences.
    static __thread char buf[128];
    int saved_errno = errno;
    snprintf(buf, sizeof(buf), "%s", strerror(err < 0 ? -err : err));
    errno = saved_errno;
    return buf;
}
