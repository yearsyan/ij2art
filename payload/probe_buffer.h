// Bounded, non-destructive flight recorder. The hot path never waits for a lock,
// allocates memory or calls the control worker. A contended hit is counted and lost.
#pragma once
#include "../common/probe_proto.h"
#include <atomic>
#include <string.h>

namespace ij2art {
class ProbeBuffer {
    static_assert(std::atomic<uint64_t>::is_always_lock_free, "lock-free probe counters required");
    std::atomic_flag lock_ = ATOMIC_FLAG_INIT;
    std::atomic<bool> enabled_{false};
    std::atomic<uint64_t> hits_{0}, captured_{0}, dropped_{0};
    uint64_t limit_ = 0;
    ij2art_probe_event events_[IJ2ART_PROBE_CAPACITY]{};
public:
    void start(uint64_t limit) {
        limit_ = limit; // immutable after publication; each buffer is used for one installation
        enabled_.store(true, std::memory_order_release);
    }
    void stop() { enabled_.store(false, std::memory_order_release); }
    bool enabled() const { return enabled_.load(std::memory_order_acquire); }
    void stats(ij2art_probe_info& info) const {
        auto hits = hits_.load(std::memory_order_relaxed);
        info.hits = limit_ && hits > limit_ ? limit_ : hits;
        info.captured = captured_.load(std::memory_order_acquire);
        info.dropped = dropped_.load(std::memory_order_relaxed);
        info.overwritten = info.captured > IJ2ART_PROBE_CAPACITY
                               ? info.captured - IJ2ART_PROBE_CAPACITY : 0;
        if (info.state == IJ2ART_PROBE_ACTIVE && limit_ && info.hits >= limit_)
            info.state = IJ2ART_PROBE_LIMITED;
    }
    template<class Fill> void capture(Fill&& fill) {
        if (!enabled()) return;
        const uint64_t hit = hits_.fetch_add(1, std::memory_order_relaxed) + 1;
        if (limit_ && hit >= limit_) {
            stop();
            if (hit > limit_) return;
        }
        if (lock_.test_and_set(std::memory_order_acquire)) {
            dropped_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        const uint64_t seq = captured_.load(std::memory_order_relaxed) + 1;
        auto& event = events_[(seq - 1) % IJ2ART_PROBE_CAPACITY];
        fill(event);
        event.seq = seq;
        event.hit = hit;
        captured_.store(seq, std::memory_order_release);
        lock_.clear(std::memory_order_release);
    }
    // Copy wire bytes with memcpy rather than treating response storage as event objects.
    // The reader also tries only once; callers may retry E_PROBE_BUSY with the same cursor.
    int read(uint64_t after, uint32_t limit, ij2art_probe_batch& batch, uint8_t* out) {
        if (!limit || limit > IJ2ART_PROBE_READ_MAX) return IJ2ART_E_PROBE_INVALID;
        if (lock_.test_and_set(std::memory_order_acquire)) return IJ2ART_E_PROBE_BUSY;
        stats(batch.info);
        const uint64_t last = batch.info.captured;
        if (after > last) {
            lock_.clear(std::memory_order_release);
            return IJ2ART_E_PROBE_INVALID;
        }
        const uint64_t oldest = last > IJ2ART_PROBE_CAPACITY ? last - IJ2ART_PROBE_CAPACITY : 0;
        batch.lost = after < oldest ? oldest - after : 0;
        uint64_t cursor = after < oldest ? oldest : after;
        batch.count = 0;
        while (cursor < last && batch.count < limit) {
            memcpy(out + batch.count * sizeof(ij2art_probe_event),
                   &events_[cursor % IJ2ART_PROBE_CAPACITY], sizeof(ij2art_probe_event));
            ++cursor;
            ++batch.count;
        }
        batch.next_seq = cursor;
        batch.more = cursor < last;
        lock_.clear(std::memory_order_release);
        return 0;
    }
};
} // namespace ij2art
