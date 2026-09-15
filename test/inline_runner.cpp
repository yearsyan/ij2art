// A fresh native child only: never inject into zygote or an existing App.
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    void* fixture = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
    void* payload = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!fixture || !payload) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    auto start = reinterpret_cast<void(*)()>(dlsym(payload, "ij2art_after_specialize"));
    if (!start) return 1;
    start();
    printf("INLINE_READY pid=%d\n", getpid());
    fflush(stdout);
    for (;;) pause();
}
