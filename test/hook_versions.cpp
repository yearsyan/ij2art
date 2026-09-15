#include "../payload/hook_versions.h"
#include <cassert>
#include <cstdio>
#include <thread>
#include <vector>

using Versions = ij2art::HookVersions<unsigned>;
int main() {
    Versions versions;
    versions.publish(new Versions::Version(1));
    auto* old = versions.acquire();
    versions.publish(new Versions::Version(2));
    auto* fresh = versions.acquire();
    assert(old->binding == 1 && fresh->binding == 2);
    unsigned collected = 0;
    versions.collect([&](unsigned) { ++collected; });
    assert(collected == 0); // A blocked old invocation pins only its own version.
    Versions::release(old);
    versions.collect([&](unsigned value) { assert(value == 1); ++collected; });
    assert(collected == 1 && fresh->binding == 2);
    Versions::release(fresh);

    std::atomic<bool> start{false}, stop{false};
    std::atomic<unsigned> calls{0};
    std::vector<std::thread> readers;
    for (int i = 0; i < 8; ++i) readers.emplace_back([&] {
        while (!start.load()) std::this_thread::yield();
        do {
            auto* version = versions.acquire();
            const unsigned selected = version->binding;
            std::this_thread::yield(); // allow publication and collection before dereferencing again
            assert(selected == version->binding && selected >= 2 && selected <= 4002);
            calls.fetch_add(1, std::memory_order_relaxed);
            Versions::release(version);
        } while (!stop.load());
    });
    start.store(true);
    for (unsigned value = 3; value <= 4002; ++value) {
        versions.publish(new Versions::Version(value));
        versions.collect([&](unsigned) { ++collected; });
    }
    stop.store(true);
    for (auto& thread : readers) thread.join();
    versions.publish(nullptr); // test teardown; production keeps the current version pinned
    versions.collect([&](unsigned) { ++collected; });
    assert(collected == 4002 && calls.load() >= 8);
    puts("PASS: callback snapshots, blocked old readers, concurrent publication and retirement");
}
