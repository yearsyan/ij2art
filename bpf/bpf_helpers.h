// The minimal set of BPF helper declarations (a replacement for libbpf's bpf_helpers.h).
// The IDs must match the order of __BPF_FUNC_MAPPER in
// third_party/kernel-uapi/include/linux/bpf.h (v5.10); see
// third_party/kernel-uapi/README.md for how to verify this.
// struct bpf_raw_tracepoint_args is already defined by linux/bpf.h and is not repeated here.
#pragma once

#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef NULL
#define NULL ((void *)0)
#endif

static void *(*bpf_map_lookup_elem)(const void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(const void *map, const void *key,
                                   const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(const void *map, const void *key) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u32 (*bpf_get_smp_processor_id)(void) = (void *)8;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_probe_read_user)(void *dst, __u32 size,
                                   const void *unsafe_ptr) = (void *)112;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size,
                                     const void *unsafe_ptr) = (void *)113;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size,
                                       const void *unsafe_ptr) = (void *)114;
static void *(*bpf_ringbuf_reserve)(const void *ringbuf, __u64 size,
                                    __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)133;
