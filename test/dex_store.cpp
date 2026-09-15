#include "../payload/dex_store.h"
#include <cassert>
#include <cstring>
#include <fstream>
#include <iterator>
#include <iostream>

int main(int argc, char** argv) {
    assert(argc == 2);
    std::ifstream input(argv[1], std::ios::binary);
    std::vector<uint8_t> dex{std::istreambuf_iterator<char>(input), {}};
    assert(dex.size() > 112);
    DexStore store(17);
    DexStore::Entry* e = nullptr;
    assert(store.begin(10, dex.size(), 100, e) == 0);
    uint64_t id = e->info.id;
    DexStore::Entry* retry = nullptr;
    assert(store.begin(10, dex.size(), 101, retry) == 0 && retry == e);
    assert(store.begin(10, dex.size()+1, 101, retry) == IJ2ART_E_STATE);
    assert(store.chunk(*e, 1, dex.data(), 1, 101) == IJ2ART_E_STATE);
    assert(store.chunk(*e, UINT64_MAX, dex.data(), 1, 101) == IJ2ART_E_INVALID);
    assert(store.validate(*e) == IJ2ART_E_STATE);
    for (size_t offset = 0; offset < dex.size(); offset += IJ2ART_CMD_DATA_MAX) {
        size_t size = std::min(size_t(IJ2ART_CMD_DATA_MAX), dex.size() - offset);
        assert(store.chunk(*e, offset, dex.data()+offset, size, 102) == 0);
        assert(store.chunk(*e, offset, dex.data()+offset, size, 103) == 0);
    }
    assert(e->info.received == dex.size());
    assert(store.validate(*e) == 0);
    uint8_t wrong = dex[0] ^ 1;
    assert(store.chunk(*e, 0, &wrong, 1, 104) == IJ2ART_E_STATE);
    e->bytes.back() ^= 1;
    assert(store.validate(*e) == IJ2ART_E_INVALID);
    e->bytes.back() ^= 1;
    e->info.hook_refs = 1;
    assert(store.drop(id) == IJ2ART_E_BUSY);
    e->info.hook_refs = 0;
    store.expire(60102);
    assert(e->info.state == IJ2ART_DEX_UPLOADING);
    store.expire(60103);
    assert(e->info.state == IJ2ART_DEX_FAILED && e->bytes.empty());
    assert(store.drop(id) == 0 && store.find(id) == nullptr);
    assert(store.begin(10, dex.size(), 70000, e) == 0 && e->info.id != id);
    assert(store.begin(0, 112, 1, retry) == IJ2ART_E_INVALID);
    assert(store.begin(11, UINT64_MAX, 1, retry) == IJ2ART_E_INVALID);
    std::cout << "PASS: DEX retries, ordering, bounds, checksum, references, expiry and nonreused ids\n";
}
