#pragma once
#include "jni_abi_constants.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace ij2art {
// Ordinary Android arm64 JNI only. This is NOT the ART quick calling convention.
struct JniCapture {
    uint64_t gp[8]; // x0 = JNIEnv*, x1 = jobject/jclass, Java GP arguments start at x2.
    uint64_t fp[8]; // Low 64 bits of v0..v7; float uses the low 32 bits.
};
enum class JniReturn : uint64_t { GP = 0, Float = 1, Double = 2, Reference = 3 };
// AAPCS64 returns this integer aggregate in x0/x1. Do not add a constructor/destructor
// or change it to a scalar: the assembly relies on BOTH registers being defined.
struct JniResult { uint64_t bits; JniReturn kind; };
enum class JniSource : uint8_t { GP, FP, Stack };
struct JniArgument { char type; JniSource source; uint16_t offset; };
struct JniLayout {
    std::vector<JniArgument> arguments;
    char result = 'V';
    uint16_t stack_bytes = 0;
};

// Parse a JVM method descriptor at installation, not on every invocation.
// On error, leave `out` unchanged. Register allocation for static and instance
// ordinary JNI is identical because both have two implicit GP arguments.
bool jni_layout(std::string_view descriptor, JniLayout& out, std::string& error);
uint64_t jni_argument_bits(const JniArgument& arg, const JniCapture& saved,
                           const void* incoming_stack);

static_assert(sizeof(JniCapture) == 128);
static_assert(offsetof(JniCapture, fp) + IJ2ART_JNI_CAPTURE_OFFSET == IJ2ART_JNI_FP_OFFSET);
static_assert(sizeof(JniCapture) + IJ2ART_JNI_CAPTURE_OFFSET == IJ2ART_JNI_FRAME_SIZE);
static_assert(sizeof(JniResult) == 16 && offsetof(JniResult, kind) == 8);
static_assert(std::is_trivial<JniResult>::value && std::is_standard_layout<JniResult>::value);
} // namespace ij2art

extern "C" {
extern void* const ij2art_jni_slots[IJ2ART_JNI_SLOTS];
// The backend provides this symbol. Exceptions must stay in JNI; C++ exceptions
// must never unwind through the assembly capture frame.
ij2art::JniResult ij2art_jni_dispatch(uint64_t slot, const ij2art::JniCapture* saved,
                                        const void* incoming_stack);
}
