#pragma once
#include "../common/art_proto.h"
#include <atomic>
#include <cstdint>

namespace ij2art {
// Admission and closing share one atomic word: once disable() returns, a reader
// that has not acquired a ticket cannot start a replacement. This counts handler
// ownership, NOT complete ART/JNI frames. Neither zero nor DISABLED permits an
// ArtMethod rewrite, slot reuse, releasing backup roots, or unloading the payload.
class HookGate {
public:
    struct Snapshot { uint32_t state; uint32_t in_flight; };

    bool try_enter() {
        uint64_t value = word_.load(std::memory_order_acquire);
        for (;;) {
            if ((value & kDisabled) || (value & kCount) == kCount) return false;
            if (word_.compare_exchange_weak(value, value + 1,
                    std::memory_order_acq_rel, std::memory_order_acquire)) return true;
        }
    }
    void leave() { word_.fetch_sub(1, std::memory_order_acq_rel); }
    void disable() { word_.fetch_or(kDisabled, std::memory_order_acq_rel); }
    Snapshot snapshot() const {
        const uint64_t value = word_.load(std::memory_order_acquire);
        const auto count = static_cast<uint32_t>(value & kCount);
        const uint32_t state = !(value & kDisabled) ? IJ2ART_HOOK_ACTIVE :
            count ? IJ2ART_HOOK_DRAINING : IJ2ART_HOOK_DISABLED;
        return {state, count};
    }
private:
    static constexpr uint64_t kDisabled = uint64_t{1} << 63;
    static constexpr uint64_t kCount = UINT32_MAX;
    std::atomic<uint64_t> word_{0};
};
} // namespace ij2art
