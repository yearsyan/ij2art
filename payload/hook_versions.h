#pragma once
#include <atomic>
#include <cstdint>
#include <mutex>
#include <utility>

namespace ij2art {
// One control-thread writer/collector, concurrent invocation readers. The short
// lock couples loading current_ with taking a lease; an atomic pointer followed
// by a refcount increment alone would race reclamation. No Java/ART call or
// allocation is allowed while this lock is held.
template<class Binding> class HookVersions {
public:
    struct Version {
        explicit Version(Binding value) : binding(std::move(value)) {}
        const Binding binding;
        std::atomic<uint32_t> users{0};
        Version* retired_next = nullptr; // control thread only
    };

    Version* acquire() {
        std::lock_guard<std::mutex> lock(mutex_);
        Version* value = current_;
        if (value) value->users.fetch_add(1, std::memory_order_relaxed);
        return value;
    }
    static void release(Version* value) {
        value->users.fetch_sub(1, std::memory_order_release);
    }
    // Ownership transfers to this process-lifetime slot. Unpublished Versions
    // remain caller-owned. current() and collect() are control-thread-only.
    void publish(Version* value) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (current_) {
            current_->retired_next = retired_;
            retired_ = current_;
        }
        current_ = value;
    }
    const Version* current() const { return current_; }
    template<class Dispose> void collect(Dispose dispose) {
        Version** link = &retired_;
        while (Version* value = *link) {
            if (value->users.load(std::memory_order_acquire) != 0) {
                link = &value->retired_next;
                continue;
            }
            *link = value->retired_next;
            dispose(value->binding);
            delete value;
        }
    }
private:
    std::mutex mutex_;
    Version* current_ = nullptr;
    Version* retired_ = nullptr;
};
} // namespace ij2art
