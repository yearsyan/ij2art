// Observation of raw_syscalls sys_enter / sys_exit (P0).
// For a raw tracepoint the ctx is (struct pt_regs *regs, long id/ret).
// The filter chain is tracked(tgid) -> policy(nr) -> ringbuf; when the ringbuf is full the
// event is counted per kind rather than dropped silently.
#include "monitor.h"

static __always_inline void bump(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&stats_map, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline __u32 cfgw(__u32 slot, __u32 dflt) {
    __u64 *v = bpf_map_lookup_elem(&cfg_map, &slot);
    return v ? (__u32)*v : dflt;
}

// The verifier cannot prove at compile time that an index read from a map is in bounds, so
// a switch pins each path (verifier-friendly).
static __always_inline __u64 sel_arg(const __u64 *a, __u8 idx) {
    switch (idx) {
    case 0: return a[0];
    case 1: return a[1];
    case 2: return a[2];
    case 3: return a[3];
    case 4: return a[4];
    case 5: return a[5];
    }
    return 0;
}

// The frame-pointer chain (x29): in each frame [fp] holds the caller's fp and [fp+8] the
// caller's lr. The loop is unrolled to a fixed 4 frames and continues only while the
// addresses increase monotonically and the step stays bounded; on failure it stops instead
// of guessing.
static __always_inline void capture_callers(struct ev_sys *ev, __u64 fp) {
    _Pragma("unroll") for (int i = 0; i < 4; i++) {
        __u64 lr = 0, next = 0;
        if (bpf_probe_read_user(&lr, 8, (const void *)(fp + 8)) != 0)
            break;
        if (bpf_probe_read_user(&next, 8, (const void *)fp) != 0)
            break;
        ev->fp[i] = lr;
        if (next <= fp || next - fp > 0x100000)
            break;
        fp = next;
    }
}

SEC("raw_tp/sys_enter")
int monitor_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    __u64 pidtgid = bpf_get_current_pid_tgid();
    __u32 tgid = pidtgid >> 32;
    if (!bpf_map_lookup_elem(&tracked_map, &tgid))
        return 0;

    __u32 nr_key = (__u32)ctx->args[1];
    struct sys_policy *p = NULL;
    if (nr_key < 512)
        p = bpf_map_lookup_elem(&policy_map, &nr_key);
    if (!p || p->action == POL_DROP)
        return 0;

    __u32 tid = (__u32)pidtgid;
    if (p->track_ret) {
        __u32 nr32 = nr_key;
        bpf_map_update_elem(&lastnr_map, &tid, &nr32, 0 /*BPF_ANY*/);
    }

    struct ev_sys *ev = bpf_ringbuf_reserve(&events_map, sizeof(*ev), 0);
    if (!ev) {
        bump(EV_SYS_ENTER * 2 + 1);
        return 0;
    }
    __builtin_memset(ev, 0, sizeof(*ev));
    ev->hdr.magic = EVMAGIC;
    ev->hdr.kind = EV_SYS_ENTER;
    ev->hdr.len = sizeof(*ev);
    ev->hdr.cpu = bpf_get_smp_processor_id();
    ev->hdr.pid = tgid;
    ev->hdr.tid = tid;
    ev->hdr.ts_ns = bpf_ktime_get_ns();
    ev->hdr.aux = nr_key;

    __u64 regs = ctx->args[0];
    __u64 a[6] = {};
    bpf_probe_read_kernel(a, 48, (const void *)regs); // x0..x5 contiguous
    __u32 pc_off = cfgw(CFG_PC_OFF, 256);
    __u32 fp_off = cfgw(CFG_FP_OFF, 232);
    bpf_probe_read_kernel(&ev->hdr.pc, 8, (const void *)(regs + pc_off));
    __u64 fp = 0;
    if (bpf_probe_read_kernel(&fp, 8, (const void *)(regs + fp_off)) == 0 && fp)
        capture_callers(ev, fp);

    if (p->action == POL_DECODE) {
        __u64 ptr = sel_arg(a, p->arg_idx);
        if (p->decoder == DEC_PATH) {
            long r = bpf_probe_read_user_str(ev->data, 96, (const void *)ptr);
            if (r < 0) {
                ev->hdr.status |= EVF_READ_FAIL;
            } else {
                if (r >= 96)
                    ev->hdr.status |= EVF_TRUNCATED;
                ev->data_len = r < 96 ? (__u16)r : 96;
            }
        } else if (p->decoder == DEC_SOCKADDR) {
            // The size passed to probe_read must be a constant, so branch on the family and
            // read a fixed length in each case. AF_INET=2 (16B), AF_INET6=10 (28B); everything
            // else grabs 26B (for example a truncated AF_UNIX path).
            __u16 fam = 0;
            if (bpf_probe_read_user(&fam, 2, (const void *)ptr) != 0) {
                ev->hdr.status |= EVF_READ_FAIL;
            } else if (fam == 2) {
                if (bpf_probe_read_user(ev->data, 16, (const void *)ptr) == 0)
                    ev->data_len = 16;
            } else if (fam == 10) {
                if (bpf_probe_read_user(ev->data, 28, (const void *)ptr) == 0)
                    ev->data_len = 28;
            } else {
                if (bpf_probe_read_user(ev->data, 26, (const void *)ptr) == 0)
                    ev->data_len = 26;
            }
        }
    }

    __builtin_memcpy(&ev->args, a, sizeof(a));
    bpf_ringbuf_submit(ev, 0);
    bump(EV_SYS_ENTER * 2);
    return 0;
}

SEC("raw_tp/sys_exit")
int monitor_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
    __u64 pidtgid = bpf_get_current_pid_tgid();
    __u32 tgid = pidtgid >> 32;
    if (!bpf_map_lookup_elem(&tracked_map, &tgid))
        return 0;
    // The sys_exit TP_PROTO carries no nr, so use the tid -> nr mapping recorded at enter
    // time. Consume and delete: enter/exit on the same thread are strictly paired, so an
    // intermediate call that policy did not admit (for example the exit of a read) cannot
    // emit an event under the wrong identity. A stale value left behind by tid reuse is
    // suppressed in the same way.
    __u32 tid = (__u32)pidtgid;
    __u32 *pnr = bpf_map_lookup_elem(&lastnr_map, &tid);
    if (!pnr)
        return 0;
    __u32 nr = *pnr;
    bpf_map_delete_elem(&lastnr_map, &tid);
    struct sys_policy *p = bpf_map_lookup_elem(&policy_map, &nr);
    if (!p || !p->track_ret)
        return 0;

    struct ev_sys *ev = bpf_ringbuf_reserve(&events_map, sizeof(*ev), 0);
    if (!ev) {
        bump(EV_SYS_EXIT * 2 + 1);
        return 0;
    }
    __builtin_memset(ev, 0, sizeof(*ev));
    ev->hdr.magic = EVMAGIC;
    ev->hdr.kind = EV_SYS_EXIT;
    ev->hdr.len = sizeof(*ev);
    ev->hdr.cpu = bpf_get_smp_processor_id();
    ev->hdr.pid = tgid;
    ev->hdr.tid = tid;
    ev->hdr.ts_ns = bpf_ktime_get_ns();
    ev->hdr.aux = nr;
    ev->ret = (long)ctx->args[1];
    bpf_ringbuf_submit(ev, 0);
    bump(EV_SYS_EXIT * 2);
    return 0;
}
