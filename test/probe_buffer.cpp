#include "../payload/probe_buffer.h"
#include <assert.h>
#include <stdio.h>
#include <thread>
#include <vector>

using ij2art::ProbeBuffer;
using Event = ij2art_probe_event;
static void fill(Event& e, uint64_t value) {
    e = {};
    e.pc = value;
    for (auto& reg : e.regs) reg = value;
}
static ij2art_probe_info stats(const ProbeBuffer& b) {
    ij2art_probe_info info{};
    info.state = IJ2ART_PROBE_ACTIVE;
    b.stats(info);
    return info;
}
int main() {
    uint8_t bytes[IJ2ART_PROBE_READ_MAX * sizeof(Event)];
    ProbeBuffer buffer;
    buffer.start(0);
    for (uint64_t i = 1; i <= 400; ++i) buffer.capture([&](Event& e) { fill(e, i); });
    ij2art_probe_batch batch{};
    assert(buffer.read(0, 48, batch, bytes) == 0);
    assert(batch.lost == 144 && batch.count == 48 && batch.next_seq == 192 && batch.more);
    Event first{};
    memcpy(&first, bytes, sizeof(first));
    assert(first.seq == 145 && first.pc == 145 && first.hit == 145);
    // Non-destructive cursors allow a timed-out read to be retried.
    assert(buffer.read(0, 48, batch, bytes) == 0 && batch.next_seq == 192 && batch.lost == 144);
    uint64_t cursor = batch.next_seq;
    do {
        assert(buffer.read(cursor, 48, batch, bytes) == 0 && batch.lost == 0);
        cursor = batch.next_seq;
    } while (batch.more);
    assert(cursor == 400);
    assert(buffer.read(cursor, 48, batch, bytes) == 0 && batch.count == 0);
    assert(buffer.read(401, 48, batch, bytes) == IJ2ART_E_PROBE_INVALID);
    assert(buffer.read(0, 49, batch, bytes) == IJ2ART_E_PROBE_INVALID);
    buffer.stop();
    buffer.capture([](Event&) { assert(false); });
    assert(stats(buffer).hits == 400);

    // Recursive callbacks and a concurrent reader never wait on their own lock.
    ProbeBuffer recursive;
    recursive.start(0);
    recursive.capture([&](Event& e) {
        recursive.capture([](Event&) { assert(false); });
        assert(recursive.read(0, 1, batch, bytes) == IJ2ART_E_PROBE_BUSY);
        fill(e, 99);
    });
    auto s = stats(recursive);
    assert(s.hits == 2 && s.captured == 1 && s.dropped == 1);

    for (uint64_t max_hits : {uint64_t{0}, uint64_t{1000}}) {
        ProbeBuffer concurrent;
        concurrent.start(max_hits);
        std::atomic<unsigned> running{8};
        std::vector<std::thread> threads;
        for (unsigned t = 0; t < 8; ++t) threads.emplace_back([&, t] {
            for (uint64_t i = 0; i < 10000; ++i)
                concurrent.capture([&](Event& e) { fill(e, (uint64_t{t} << 32) | i); });
            --running;
        });
        uint64_t after = 0;
        while (running.load()) {
            const int err = concurrent.read(after, 48, batch, bytes);
            if (err == IJ2ART_E_PROBE_BUSY) continue;
            assert(err == 0);
            for (uint32_t i = 0; i < batch.count; ++i) {
                Event event{};
                memcpy(&event, bytes + i * sizeof(Event), sizeof(event));
                assert(event.seq > after);
                for (auto reg : event.regs) assert(reg == event.pc); // no torn snapshots
                after = event.seq;
            }
            assert(after == batch.next_seq);
        }
        for (auto& thread : threads) thread.join();
        s = stats(concurrent);
        assert(s.hits == (max_hits ? max_hits : 80000));
        assert(s.captured + s.dropped == s.hits);
        assert(s.overwritten == (s.captured > 256 ? s.captured - 256 : 0));
        if (max_hits) assert(s.state == IJ2ART_PROBE_LIMITED && !concurrent.enabled());
    }
    puts("PASS: probe buffer pagination, retry, overflow, reentrancy, concurrent snapshots and hit limits");
}
