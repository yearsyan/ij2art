#include "jni_abi.h"
#include <cstring>
#include <utility>

namespace ij2art {
namespace {
bool type(std::string_view text, size_t& cursor, char& kind, bool allow_void) {
    if (cursor >= text.size()) return false;
    kind = text[cursor++];
    if (kind == 'V') return allow_void;
    if (std::string_view("ZBCSIJFD").find(kind) != std::string_view::npos) return true;
    if (kind == 'L') {
        size_t start = cursor;
        while (cursor < text.size() && text[cursor] != ';') {
            char c = text[cursor++];
            if (c <= 0x20 || c >= 0x7f || c == '.' || c == '[' || c == '(' || c == ')') return false;
        }
        if (cursor == start || cursor == text.size()) return false;
        ++cursor;
        return true;
    }
    if (kind == '[') {
        size_t dimensions = 1;
        while (cursor < text.size() && text[cursor] == '[') { ++dimensions; ++cursor; }
        char element;
        if (dimensions > 255 || !type(text, cursor, element, false)) return false;
        kind = 'L';
        return true;
    }
    return false;
}
} // namespace

bool jni_layout(std::string_view descriptor, JniLayout& out, std::string& error) {
    JniLayout next;
    size_t cursor = 1;
    unsigned gp = 2, fp = 0, units = 0;
    if (descriptor.empty() || descriptor.front() != '(') {
        error = "expected JVM method descriptor";
        return false;
    }
    while (cursor < descriptor.size() && descriptor[cursor] != ')') {
        char kind;
        if (!type(descriptor, cursor, kind, false) ||
            (units += (kind == 'J' || kind == 'D') ? 2 : 1) > 255) {
            error = "invalid parameter type or more than 255 parameter units";
            return false;
        }
        bool floating = kind == 'F' || kind == 'D';
        unsigned& reg = floating ? fp : gp;
        if (reg < 8) {
            next.arguments.push_back({kind, floating ? JniSource::FP : JniSource::GP,
                                      static_cast<uint16_t>(reg++ * 8)});
        } else {
            // Both exhausted banks share ONE stack cursor in declaration order.
            // Every Java scalar occupies an 8-byte stack slot under Android AAPCS64.
            next.arguments.push_back({kind, JniSource::Stack, next.stack_bytes});
            next.stack_bytes += 8;
        }
    }
    if (cursor >= descriptor.size() || descriptor[cursor++] != ')' ||
        !type(descriptor, cursor, next.result, true) || cursor != descriptor.size()) {
        error = "invalid return type or trailing descriptor data";
        return false;
    }
    out = std::move(next);
    error.clear();
    return true;
}

uint64_t jni_argument_bits(const JniArgument& arg, const JniCapture& saved,
                           const void* incoming_stack) {
    const void* base = arg.source == JniSource::GP ? static_cast<const void*>(saved.gp) :
                       arg.source == JniSource::FP ? static_cast<const void*>(saved.fp) : incoming_stack;
    // Upper bits of narrow arguments are unspecified. Never interpret them as
    // a sign extension or read all 8 stack bytes for a 32-bit float.
    size_t width = arg.type == 'J' || arg.type == 'D' || arg.type == 'L' ? 8 :
                   arg.type == 'I' || arg.type == 'F' ? 4 :
                   arg.type == 'C' || arg.type == 'S' ? 2 : 1;
    uint64_t bits = 0;
    std::memcpy(&bits, static_cast<const uint8_t*>(base) + arg.offset, width);
    return bits;
}
} // namespace ij2art
