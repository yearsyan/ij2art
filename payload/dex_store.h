#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "../common/art_proto.h"

// Owned exclusively by the control worker. JNI references are managed by art.cpp.
class DexStore {
public:
    struct Entry {
        ij2art_dex_info info{};
        std::vector<uint8_t> bytes;
        uint64_t touched_ms = 0;
        std::string failure;
    };
    explicit DexStore(uint32_t namespace_id) : next_(uint64_t(namespace_id) << 32) {}
    int begin(uint64_t nonce, uint64_t size, uint64_t now, Entry*& out);
    int chunk(Entry& entry, uint64_t offset, const uint8_t* bytes, size_t size, uint64_t now);
    int validate(const Entry& entry) const;
    Entry* find(uint64_t id);
    Entry* by_nonce(uint64_t nonce);
    int drop(uint64_t id);
    void fail(Entry& entry, int error, const std::string& message);
    void expire(uint64_t now);
    const std::array<Entry, IJ2ART_DEX_SLOTS>& entries() const { return entries_; }
private:
    std::array<Entry, IJ2ART_DEX_SLOTS> entries_{};
    uint64_t next_;
};
