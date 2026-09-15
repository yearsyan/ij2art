#include "../payload/hook_gate.h"
#include <atomic>
#include <cassert>
#include <cstdio>
#include <thread>
#include <vector>

using ij2art::HookGate;

int main() {
    // A paused, admitted handler owns its ticket until it finishes, even after
    // closing. New original forwarding does not prolong that drain.
    HookGate gate;
    std::atomic<bool> entered{false}, release{false};
    std::thread handler([&] {
        assert(gate.try_enter());
        entered.store(true, std::memory_order_release);
        while (!release.load(std::memory_order_acquire)) std::this_thread::yield();
        gate.leave();
    });
    while (!entered.load(std::memory_order_acquire)) std::this_thread::yield();
    gate.disable();
    assert(gate.snapshot().state == IJ2ART_HOOK_DRAINING);
    assert(gate.snapshot().in_flight == 1);
    for (unsigned i = 0; i < 100000; ++i) assert(!gate.try_enter());
    release.store(true, std::memory_order_release);
    handler.join();
    assert(gate.snapshot().state == IJ2ART_HOOK_DISABLED);
    assert(gate.snapshot().in_flight == 0);
    gate.disable();
    assert(!gate.try_enter());

    // Readers contend with the closer. Each accepted ticket is released once;
    // a reader observing completion of disable must never acquire a new ticket.
    for (unsigned round = 0; round < 100; ++round) {
        HookGate concurrent;
        std::atomic<unsigned> ready{0};
        std::atomic<bool> start{false}, closed{false};
        std::vector<std::thread> readers;
        for (unsigned n = 0; n < 4; ++n) readers.emplace_back([&] {
            ready.fetch_add(1);
            while (!start.load()) std::this_thread::yield();
            while (!closed.load(std::memory_order_acquire)) {
                if (concurrent.try_enter()) concurrent.leave();
            }
            for (unsigned i = 0; i < 1000; ++i) assert(!concurrent.try_enter());
        });
        while (ready.load() != 4) std::this_thread::yield();
        start.store(true);
        concurrent.disable();
        closed.store(true, std::memory_order_release);
        for (auto& reader : readers) reader.join();
        assert(concurrent.snapshot().state == IJ2ART_HOOK_DISABLED);
        assert(concurrent.snapshot().in_flight == 0);
    }
    std::puts("PASS: atomic replacement admission, blocked-handler drain, late readers, idempotent disable");
}
