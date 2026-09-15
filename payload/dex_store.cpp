#include "dex_store.h"
#include <cstring>
#include <limits>
#include <new>

static uint32_t u32(const uint8_t* p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
DexStore::Entry* DexStore::find(uint64_t id) {
    for (auto& e : entries_) if (id && e.info.id == id) return &e;
    return nullptr;
}
DexStore::Entry* DexStore::by_nonce(uint64_t nonce) {
    for (auto& e : entries_) if (nonce && e.info.nonce == nonce) return &e;
    return nullptr;
}
int DexStore::begin(uint64_t nonce, uint64_t size, uint64_t now, Entry*& out) {
    out = nullptr;
    if (!nonce || size < 112 || size > IJ2ART_DEX_MAX) return IJ2ART_E_INVALID;
    if (auto* existing = by_nonce(nonce)) {
        if (existing->info.size != size) return IJ2ART_E_STATE;
        out = existing;
        return 0;
    }
    uint64_t allocated = 0;
    Entry* free = nullptr;
    for (auto& e : entries_) {
        // Loaded DEX data remains charged even after native staging bytes are released.
        if (e.info.state != IJ2ART_DEX_FAILED) allocated += e.info.size;
        if (!e.info.id) free = &e;
    }
    if (!free || allocated + size > IJ2ART_DEX_TOTAL_MAX ||
        (next_ & UINT32_MAX) == UINT32_MAX) return IJ2ART_E_LIMIT;
    try { free->bytes.resize(size); } catch (const std::bad_alloc&) { return IJ2ART_E_LIMIT; }
    free->info = {++next_, nonce, size, 0, IJ2ART_DEX_UPLOADING, 0, 0, 0};
    free->touched_ms = now;
    out = free;
    return 0;
}
int DexStore::chunk(Entry& e, uint64_t offset, const uint8_t* bytes, size_t size, uint64_t now) {
    if (e.info.state != IJ2ART_DEX_UPLOADING) return IJ2ART_E_STATE;
    if (!size || size > IJ2ART_CMD_DATA_MAX || offset > e.info.size || size > e.info.size - offset)
        return IJ2ART_E_INVALID;
    if (offset < e.info.received) {
        if (size > e.info.received - offset || std::memcmp(e.bytes.data() + offset, bytes, size))
            return IJ2ART_E_STATE;
    } else {
        if (offset != e.info.received) return IJ2ART_E_STATE;
        std::memcpy(e.bytes.data() + offset, bytes, size);
        e.info.received += size;
    }
    e.touched_ms = now;
    return 0;
}
int DexStore::validate(const Entry& e) const {
    if (e.info.state != IJ2ART_DEX_UPLOADING || e.info.received != e.info.size)
        return IJ2ART_E_STATE;
    const auto& b = e.bytes;
    if (b.size() < 112 || std::memcmp(b.data(), "dex\n", 4) || b[7] != 0 ||
        (std::memcmp(b.data()+4, "035", 3) && std::memcmp(b.data()+4, "037", 3) &&
         std::memcmp(b.data()+4, "038", 3) && std::memcmp(b.data()+4, "039", 3) &&
         std::memcmp(b.data()+4, "040", 3)) ||
        u32(b.data()+32) != b.size() || u32(b.data()+36) != 112 || u32(b.data()+40) != 0x12345678)
        return IJ2ART_E_INVALID;
    uint32_t a = 1, sum = 0;
    for (size_t n = 12; n < b.size(); ++n) { a = (a + b[n]) % 65521; sum = (sum + a) % 65521; }
    if ((sum << 16 | a) != u32(b.data()+8)) return IJ2ART_E_INVALID;
    return 0; // ART validates the DEX tables/code; this checks transport integrity and supported format.
}
int DexStore::drop(uint64_t id) {
    auto* e = find(id);
    if (!e) return IJ2ART_E_NOT_FOUND;
    if (e->info.hook_refs) return IJ2ART_E_BUSY;
    *e = Entry{};
    return 0;
}
void DexStore::fail(Entry& e, int error, const std::string& message) {
    e.info.state = IJ2ART_DEX_FAILED;
    e.info.error = error;
    e.failure = message;
    std::vector<uint8_t>().swap(e.bytes);
}
void DexStore::expire(uint64_t now) {
    for (auto& e : entries_) {
        if (e.info.state == IJ2ART_DEX_UPLOADING && now >= e.touched_ms && now - e.touched_ms >= 60000)
            fail(e, IJ2ART_E_STATE, "incomplete DEX upload expired; delete the entry before retrying");
    }
}
