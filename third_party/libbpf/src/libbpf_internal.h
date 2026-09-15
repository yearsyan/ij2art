/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Helpers extracted verbatim from libbpf v1.7.0 src/libbpf_internal.h.
 * Copyright (c) 2019 Facebook. See README.md for the extraction boundary.
 * No ring buffer algorithm or memory barrier is implemented here.
 */
#pragma once
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <linux/compiler.h>
#include "libbpf.h"
#define offsetofend(TYPE, FIELD) (offsetof(TYPE, FIELD) + sizeof(((TYPE *)0)->FIELD))
extern void libbpf_print(enum libbpf_print_level level,
			 const char *format, ...)
	__attribute__((format(printf, 2, 3)));

#define __pr(level, fmt, ...)	\
do {				\
	libbpf_print(level, "libbpf: " fmt, ##__VA_ARGS__);	\
} while (0)

#define pr_warn(fmt, ...)	__pr(LIBBPF_WARN, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...)	__pr(LIBBPF_INFO, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...)	__pr(LIBBPF_DEBUG, fmt, ##__VA_ARGS__)

/**
 * @brief **libbpf_errstr()** returns string corresponding to numeric errno
 * @param err negative numeric errno
 * @return pointer to string representation of the errno, that is invalidated
 * upon the next call.
 */
const char *libbpf_errstr(int err);

#define errstr(err) libbpf_errstr(err)


static inline void *libbpf_reallocarray(void *ptr, size_t nmemb, size_t size)
{
	size_t total;

#if __has_builtin(__builtin_mul_overflow)
	if (unlikely(__builtin_mul_overflow(nmemb, size, &total)))
		return NULL;
#else
	if (size == 0 || nmemb > ULONG_MAX / size)
		return NULL;
	total = nmemb * size;
#endif
	return realloc(ptr, total);
}


static inline bool libbpf_is_mem_zeroed(const char *p, ssize_t len)
{
	while (len > 0) {
		if (*p)
			return false;
		p++;
		len--;
	}
	return true;
}

static inline bool libbpf_validate_opts(const char *opts,
					size_t opts_sz, size_t user_sz,
					const char *type_name)
{
	if (user_sz < sizeof(size_t)) {
		pr_warn("%s size (%zu) is too small\n", type_name, user_sz);
		return false;
	}
	if (!libbpf_is_mem_zeroed(opts + opts_sz, (ssize_t)user_sz - opts_sz)) {
		pr_warn("%s has non-zero extra bytes\n", type_name);
		return false;
	}
	return true;
}

#define OPTS_VALID(opts, type)						      \
	(!(opts) || libbpf_validate_opts((const char *)opts,		      \
					 offsetofend(struct type,	      \
						     type##__last_field),     \
					 (opts)->sz, #type))

static inline int libbpf_err(int ret)
{
	if (ret < 0)
		errno = -ret;
	return ret;
}

/* handle errno-based (e.g., syscall or libc) errors according to libbpf's
 * strict mode settings
 */
static inline int libbpf_err_errno(int ret)
{
	/* errno is already assumed to be set on error */
	return ret < 0 ? -errno : ret;
}

