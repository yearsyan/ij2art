// Experimental proof ONLY; deliberately excluded from payload/build.sh.
// Bound to the checked Android 16 arm64 libart build and the Java fixture above.
// No LSPlant, inline-hook library, runtime code emitter or executable allocator.
#include "../payload/jni_abi.h"
#include <jni.h>
#include <elf.h>
#include <link.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <atomic>
#include <cstring>
#include <string>
#include <vector>

using namespace ij2art;
namespace {
constexpr char build_id[] = "7bf2886127ae5230f6030d2e8fa42561";

bool span(size_t size, uint64_t offset, uint64_t length) {
    return offset <= size && length <= size - offset;
}

std::string note_id(const uint8_t* bytes, size_t remaining) {
    while (remaining >= sizeof(Elf64_Nhdr)) {
        Elf64_Nhdr note{};
        std::memcpy(&note, bytes, sizeof(note));
        uint64_t names = (uint64_t(note.n_namesz) + 3) & ~uint64_t(3);
        uint64_t desc = (uint64_t(note.n_descsz) + 3) & ~uint64_t(3);
        uint64_t total = sizeof(note) + names + desc;
        if (total > remaining) break;
        if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4 &&
            !std::memcmp(bytes + sizeof(note), "GNU", 4) && note.n_descsz <= 64) {
            std::string result;
            for (size_t i = 0; i < note.n_descsz; ++i) {
                const char* hex = "0123456789abcdef";
                uint8_t value = bytes[sizeof(note) + names + i];
                result += hex[value >> 4];
                result += hex[value & 15];
            }
            return result;
        }
        bytes += total;
        remaining -= total;
    }
    return {};
}

struct Symbols {
    uintptr_t base = 0;
    std::string path;
    std::vector<std::pair<std::string, void*>> entries;

    bool init() {
        dl_iterate_phdr([](dl_phdr_info* info, size_t, void* data) {
            auto& self = *static_cast<Symbols*>(data);
            const char* name = std::strrchr(info->dlpi_name, '/');
            if (!name || std::strcmp(name, "/libart.so")) return 0;
            for (size_t i = 0; i < info->dlpi_phnum; ++i) {
                const auto& ph = info->dlpi_phdr[i];
                if (ph.p_type == PT_NOTE &&
                    note_id(reinterpret_cast<const uint8_t*>(info->dlpi_addr + ph.p_vaddr), ph.p_memsz) == build_id) {
                    self.base = info->dlpi_addr;
                    self.path = info->dlpi_name;
                }
            }
            return 1;
        }, this);
        if (!base) return false;
        int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) return false;
        struct stat st{};
        if (fstat(fd, &st) || st.st_size < static_cast<off_t>(sizeof(Elf64_Ehdr))) {
            close(fd);
            return false;
        }
        size_t size = st.st_size;
        auto* bytes = static_cast<const uint8_t*>(mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0));
        close(fd);
        if (bytes == MAP_FAILED) return false;
        bool ok = read(bytes, size);
        munmap(const_cast<uint8_t*>(bytes), size);
        return ok;
    }

    bool read(const uint8_t* bytes, size_t size) {
        Elf64_Ehdr elf{};
        std::memcpy(&elf, bytes, sizeof(elf));
        if (std::memcmp(elf.e_ident, ELFMAG, SELFMAG) || elf.e_ident[EI_CLASS] != ELFCLASS64 ||
            elf.e_ident[EI_DATA] != ELFDATA2LSB || elf.e_machine != EM_AARCH64 ||
            elf.e_shentsize != sizeof(Elf64_Shdr) || !elf.e_shnum ||
            !span(size, elf.e_shoff, uint64_t(elf.e_shnum) * sizeof(Elf64_Shdr))) return false;
        std::vector<Elf64_Shdr> sections(elf.e_shnum);
        std::memcpy(sections.data(), bytes + elf.e_shoff, sections.size() * sizeof(Elf64_Shdr));
        bool matching_file = false;
        for (const auto& section : sections) {
            if (!span(size, section.sh_offset, section.sh_size)) continue;
            if (section.sh_type == SHT_NOTE && note_id(bytes + section.sh_offset, section.sh_size) == build_id)
                matching_file = true;
            if (section.sh_type != SHT_SYMTAB && section.sh_type != SHT_DYNSYM) continue;
            if (section.sh_link >= sections.size() || section.sh_entsize != sizeof(Elf64_Sym) ||
                section.sh_size % sizeof(Elf64_Sym)) continue;
            const auto& strings = sections[section.sh_link];
            if (strings.sh_type != SHT_STRTAB || !span(size, strings.sh_offset, strings.sh_size)) continue;
            for (size_t at = 0; at < section.sh_size; at += sizeof(Elf64_Sym)) {
                Elf64_Sym symbol{};
                std::memcpy(&symbol, bytes + section.sh_offset + at, sizeof(symbol));
                if (symbol.st_shndx == SHN_UNDEF || !symbol.st_value || symbol.st_name >= strings.sh_size ||
                    ELF64_ST_TYPE(symbol.st_info) != STT_FUNC) continue;
                const char* name = reinterpret_cast<const char*>(bytes + strings.sh_offset + symbol.st_name);
                size_t max = strings.sh_size - symbol.st_name;
                size_t length = strnlen(name, max);
                if (length < max) entries.emplace_back(std::string(name, length), reinterpret_cast<void*>(base + symbol.st_value));
            }
        }
        return matching_file && !entries.empty();
    }

    template<class T> T get(const char* name) const {
        for (const auto& entry : entries) if (entry.first == name) return reinterpret_cast<T>(entry.second);
        return nullptr;
    }
};

// AOSP android-16.0.0_r1 art_method.h, checked against this device build.
// These constants are NOT selected by API level, and are not a portable adapter.
struct ArtMethod {
    uint32_t klass, flags, dex_index;
    uint16_t index, counter;
    void* data;
    void* quick;
};
static_assert(sizeof(ArtMethod) == 32 && offsetof(ArtMethod, data) == 16);
constexpr uint32_t no_compile = 0x02000000, precompiled = 0x00800000;
constexpr uint32_t nterp_invoke = 0x00200000, nterp_entry_or_critical = 0x00100000;
constexpr uint32_t skip_checks_or_fast = 0x00080000, native_flag = 0x100;

// Deliberately process-lifetime roots in this disposable fixture, not an unload policy.
jobject original, replacement, target_ref;
jclass bridge, fixture;
jmethodID dispatch, invoke_backup, int_value;
JniLayout layout;
std::atomic<uint64_t> sequence{1};
thread_local uint64_t active;

jobject call_original(JNIEnv* env, jclass, jlong id, jobject receiver, jobjectArray args) {
    if (!active || uint64_t(id) != active) {
        jclass error = env->FindClass("java/lang/IllegalStateException");
        if (error) env->ThrowNew(error, "invalid original token");
        return nullptr;
    }
    return env->CallStaticObjectMethod(fixture, invoke_backup, original, receiver, args);
}
} // namespace

extern "C" JniResult ij2art_jni_dispatch(uint64_t slot, const JniCapture* saved, const void* stack) {
    auto* env = reinterpret_cast<JNIEnv*>(saved->gp[0]);
    if (slot != 0) return {0, JniReturn::GP};
    uint64_t bits = jni_argument_bits(layout.arguments[0], *saved, stack);
    jclass integer = env->FindClass("java/lang/Integer");
    if (!integer) return {0, JniReturn::GP};
    jmethodID factory = env->GetStaticMethodID(integer, "valueOf", "(I)Ljava/lang/Integer;");
    if (!factory) return {0, JniReturn::GP};
    jclass object = env->FindClass("java/lang/Object");
    if (!object) return {0, JniReturn::GP};
    jobjectArray args = env->NewObjectArray(1, object, nullptr);
    if (!args) return {0, JniReturn::GP};
    jobject arg = env->CallStaticObjectMethod(integer, factory, jint(bits));
    if (env->ExceptionCheck()) return {0, JniReturn::GP};
    env->SetObjectArrayElement(args, 0, arg);
    if (env->ExceptionCheck()) return {0, JniReturn::GP};
    uint64_t previous = active;
    active = sequence.fetch_add(1);
    jobject result = env->CallStaticObjectMethod(bridge, dispatch, jlong(active), target_ref, nullptr, args, replacement);
    active = previous;
    if (env->ExceptionCheck() || !result) return {0, JniReturn::GP};
    jint value = env->CallIntMethod(result, int_value);
    return {uint64_t(uint32_t(value)), JniReturn::GP};
}

extern "C" JNIEXPORT jobject JNICALL Java_org_ij2art_StaticOriginal_install(
    JNIEnv* env, jclass cls, jobject target, jobject backup, jobject handler) {
    if (original) return nullptr; // One install, no reuse in this fixture.
    Symbols symbols;
    if (!symbols.init()) return nullptr; // No ART mutation on another build.
    auto suspend = symbols.get<void(*)(void*, const char*, bool)>("_ZN3art16ScopedSuspendAllC1EPKcb");
    auto resume = symbols.get<void(*)(void*)>("_ZN3art16ScopedSuspendAllD1Ev");
    auto gc_enter = symbols.get<void(*)(void*, void*, int, int)>(
        "_ZN3art2gc23ScopedGCCriticalSectionC1EPNS_6ThreadENS0_7GcCauseENS0_13CollectorTypeE");
    auto gc_exit = symbols.get<void(*)(void*)>("_ZN3art2gc23ScopedGCCriticalSectionD1Ev");
    auto current = symbols.get<void*(*)()>("_ZN3art6Thread14CurrentFromGdbEv");
    auto copy = symbols.get<void(*)(ArtMethod*, ArtMethod*, size_t)>("_ZN3art9ArtMethod8CopyFromEPS0_NS_11PointerSizeE");
    void* generic = symbols.get<void*>("art_quick_generic_jni_trampoline");
    void* interpreter = symbols.get<void*>("art_quick_to_interpreter_bridge");
    if (!suspend || !resume || !gc_enter || !gc_exit || !current || !copy || !generic || !interpreter)
        return nullptr;
    jclass executable = env->FindClass("java/lang/reflect/Executable");
    if (!executable) return nullptr;
    jfieldID field = env->GetFieldID(executable, "artMethod", "J");
    if (!field) return nullptr;
    auto* t = reinterpret_cast<ArtMethod*>(env->GetLongField(target, field));
    auto* b = reinterpret_cast<ArtMethod*>(env->GetLongField(backup, field));
    jmethodID id = env->FromReflectedMethod(backup); // A real ART-created method and JNI ID.
    if (!id || !t || !b || t == b) return nullptr;
    jclass context = env->FindClass("org/ij2art/HookContext");
    if (!context) return nullptr;
    JNINativeMethod native{const_cast<char*>("callOriginalNative"),
        const_cast<char*>("(JLjava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"), (void*)call_original};
    if (env->RegisterNatives(context, &native, 1) != JNI_OK) return nullptr;
    fixture = static_cast<jclass>(env->NewGlobalRef(cls));
    if (!fixture) return nullptr;
    jclass br = env->FindClass("org/ij2art/Bridge");
    if (!br) return nullptr;
    bridge = static_cast<jclass>(env->NewGlobalRef(br));
    if (!bridge) return nullptr;
    dispatch = env->GetStaticMethodID(bridge, "dispatch",
        "(JLjava/lang/reflect/Executable;Ljava/lang/Object;[Ljava/lang/Object;Ljava/lang/reflect/Method;)Ljava/lang/Object;");
    if (!dispatch) return nullptr;
    invoke_backup = env->GetStaticMethodID(fixture, "invokeBackup",
        "(Ljava/lang/reflect/Method;Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
    if (!invoke_backup) return nullptr;
    jclass integer = env->FindClass("java/lang/Integer");
    if (!integer) return nullptr;
    int_value = env->GetMethodID(integer, "intValue", "()I");
    if (!int_value) return nullptr;
    replacement = env->NewGlobalRef(handler);
    if (!replacement) return nullptr;
    target_ref = env->NewGlobalRef(target);
    if (!target_ref) return nullptr;
    std::string error;
    if (!jni_layout("(I)I", layout, error)) return nullptr;

    // Fixture-specific admission: public static concrete, same initialized class,
    // ordinary non-intrinsic/non-synchronized managed methods with CodeItems.
    // The Java fixture establishes that no target frame or compiled caller exists.
    alignas(8) unsigned char gc[24]{}; // ScopedGCCriticalSection for this build.
    unsigned char stop{};             // ScopedSuspendAll has no fields.
    // Android 16: kGcCauseInstrumentation=8, kCollectorTypeInstrumentation=9.
    gc_enter(gc, current(), 8, 9);
    suspend(&stop, "ij2art static JNI proof", false);
    // Even admission reads of declaring-class roots require the ART lock.
    if ((t->flags & 0xffff) != 9 || (b->flags & 0xffff) != 9 ||
        (t->flags & 0x80020000) || !t->data || !b->data || t->klass != b->klass) {
        resume(&stop);
        gc_exit(gc);
        return nullptr;
    }
    copy(b, t, 8); // ART handles the declaring-class root and copied code metadata.
    b->flags = (b->flags | no_compile) & ~(precompiled | nterp_invoke | nterp_entry_or_critical);
    b->quick = interpreter; // Never retain a reclaimable compiled entry address.
    t->data = ij2art_jni_slots[0];
    t->flags = (t->flags | no_compile | native_flag) &
        ~(precompiled | nterp_invoke | nterp_entry_or_critical | skip_checks_or_fast);
    t->quick = generic;
    resume(&stop);
    gc_exit(gc);
    // Only this fixture thread can call the target. Production must publish
    // everything BEFORE opening admissions, and coordinate failures/old frames.
    jobject reflected = env->ToReflectedMethod(cls, id, JNI_TRUE);
    if (!reflected) return nullptr;
    original = env->NewGlobalRef(reflected);
    return original ? reflected : nullptr;
}
