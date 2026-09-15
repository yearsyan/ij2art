#include <atomic>
#include <stdint.h>
#include <string.h>
#include <thread>
#include <vector>

#define EXPORT extern "C" __attribute__((visibility("default"), noinline))
extern "C" {
void* native_original;
void* fp_original;
void* sum_original;
void* adr_original;
void* adrp_original;
void* literal_original;
void* branch_original;
void* cbz_original;
void* pac_original;
void* ppid_original;
uint64_t reloc_adr(uint64_t);
uint64_t reloc_adrp(uint64_t);
uint64_t reloc_literal(uint64_t);
uint64_t reloc_branch(uint64_t);
uint64_t reloc_cbz(uint64_t);
uint64_t reloc_pac(uint64_t);
}
template<class F> F original(void** slot) {
    return reinterpret_cast<F>(__atomic_load_n(slot, __ATOMIC_ACQUIRE));
}
EXPORT uint64_t native_target(uint64_t a, uint64_t b) { return a * 3 + b; }
EXPORT uint64_t target_address() { return reinterpret_cast<uint64_t>(&native_target); }
EXPORT uint64_t native_proxy(uint64_t a, uint64_t b) {
    auto fn = original<uint64_t(*)(uint64_t,uint64_t)>(&native_original);
    return fn ? fn(a,b) + 1000 : UINT64_MAX;
}
EXPORT uint64_t constant_proxy(uint64_t, uint64_t) { return 99; }
EXPORT int ppid_proxy() { return original<int(*)()>(&ppid_original)() + 1; }
EXPORT double native_fp(double a, double b) { return a * 1.5 + b; }
EXPORT double fp_proxy(double a, double b) {
    return original<double(*)(double,double)>(&fp_original)(a,b) + 0.25;
}
EXPORT uint64_t probe_fp() {
    double (*volatile fn)(double,double) = native_fp;
    double value = fn(2.0, 4.0);
    uint64_t bits;
    memcpy(&bits, &value, sizeof(bits));
    return bits;
}
using Sum = uint64_t(*)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
EXPORT uint64_t native_sum10(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,
                             uint64_t f,uint64_t g,uint64_t h,uint64_t i,uint64_t j) {
    return a+2*b+3*c+4*d+5*e+6*f+7*g+8*h+9*i+10*j;
}
EXPORT uint64_t sum_proxy(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,
                          uint64_t f,uint64_t g,uint64_t h,uint64_t i,uint64_t j) {
    return original<Sum>(&sum_original)(a,b,c,d,e,f,g,h,i,j) + 1000;
}
EXPORT uint64_t probe_sum() {
    Sum volatile fn = native_sum10;
    return fn(1,2,3,4,5,6,7,8,9,10);
}
#define RELOC_PROXY(name) EXPORT uint64_t name##_proxy(uint64_t value) { \
    return original<uint64_t(*)(uint64_t)>(&name##_original)(value) + 100; }
RELOC_PROXY(adr)
RELOC_PROXY(adrp)
RELOC_PROXY(literal)
RELOC_PROXY(branch)
RELOC_PROXY(cbz)
RELOC_PROXY(pac)

std::atomic<bool> running{false};
std::atomic<uint64_t> errors{0}, calls{0}, hooked{0};
std::vector<std::thread> workers;
EXPORT uint64_t start_workers() {
    if (running.exchange(true)) return 0;
    for (int i=0; i<4; ++i) workers.emplace_back([] {
        uint64_t (*volatile fn)(uint64_t,uint64_t) = native_target;
        while (running.load(std::memory_order_relaxed)) {
            uint64_t value = fn(3,2);
            if (value != 11 && value != 1011) ++errors;
            if (value == 1011) ++hooked;
            ++calls;
        }
    });
    return 1;
}
EXPORT uint64_t stop_workers() {
    running.store(false);
    for (auto& worker: workers) worker.join();
    workers.clear();
    return errors.load();
}
EXPORT uint64_t worker_calls() { return calls.load(); }
EXPORT uint64_t worker_hooked() { return hooked.load(); }
