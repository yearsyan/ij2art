package org.ij2art.test;

import java.lang.reflect.Modifier;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Exercise strict admission and logical disable on actual managed targets. */
public final class AdmissionMain {
    private static native void start(String payload, ClassLoader loader);
    private static native int processId();
    private static final CountDownLatch entered = new CountDownLatch(1);
    private static final CountDownLatch release = new CountDownLatch(1);
    public static int cold(int value) { return value + 1; }
    public static int pattern(int value) { return 1; }
    private static boolean lazyInitialized;
    public static final class Lazy {
        static { lazyInitialized = true; }
        public static int cold(int value) { return value + 1; }
    }
    public static final class Broken {
        static { if (System.nanoTime() != 0) throw new IllegalStateException("fixture clinit failure"); }
        public static int cold(int value) { return value + 1; }
    }
    public abstract static class Base { public abstract int value(int n); }
    public static final class First extends Base { @Override public int value(int n) { return n; } }
    public static final class Derived extends Base { @Override public int value(int n) { return n + 1; } }
    private static Base receiver = new First();
    public static int osr(int value) {
        int result = 0;
        for (int i = 0; i < value; ++i) result += receiver.value(i);
        return result;
    }
    private static native long codeState(Method method, int compileKind);
    private static native void collectCode();
    private static native int runtimeMode();
    private static native boolean hasPatternStubs();
    private static native boolean opaqueIds();
    private static void compile(Method method, int kind, long wanted) throws Exception {
        codeState(method, kind);
        for (int i = 0; i < 1000; ++i) {
            long state = codeState(method, -1);
            if ((kind == 0 ? state & 0x10000 : state & 0xffff) >= wanted) return;
            if (i % 10 == 0) codeState(method, kind);
            Thread.sleep(10);
        }
        throw new AssertionError("compile failed: " + method + " kind=" + kind);
    }
    private static volatile int hotCounter;
    public static int hot(int value) { hotCounter += value; return value * 2; }
    private static native void holdJit();
    private static native void releaseJit();
    public static int active(int value) throws Exception {
        entered.countDown();
        if (!release.await(120, TimeUnit.SECONDS)) throw new AssertionError("release timeout");
        return value + 1;
    }
    private static void check(boolean ok) { if (!ok) throw new AssertionError(); }
    private static void awaitPhase(String path, int want) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(120);
        while (System.nanoTime() < deadline) {
            try {
                if (Integer.parseInt(new String(Files.readAllBytes(Paths.get(path))).trim()) == want) return;
            } catch (java.io.IOException ignored) { }
              catch (NumberFormatException ignored) { }
            Thread.sleep(20);
        }
        throw new AssertionError("phase timeout " + want);
    }
    public static void main(String[] args) {
        System.load(args[0]);
        System.out.println("FIXTURE_PID=" + processId());
        try { run(args); }
        catch (Throwable failure) {
            failure.printStackTrace(System.out);
            System.out.println("HOOK_TEST_FAIL " + failure);
            System.exit(1);
        }
    }
    private static void run(String[] args) throws Exception {
        start(args[1], AdmissionMain.class.getClassLoader());
        int mode = runtimeMode();
        check(mode >= 0);
        boolean jit = (mode & 1) != 0;
        System.out.println("RUNTIME_MODE=" + mode);
        System.out.println("OPAQUE_IDS=" + opaqueIds());
        Method hotMethod = AdmissionMain.class.getDeclaredMethod("hot", int.class);
        Method osrMethod = AdmissionMain.class.getDeclaredMethod("osr", int.class);
        Method patternMethod = AdmissionMain.class.getDeclaredMethod("pattern", int.class);
        if (jit) {
            if ((mode & 2) == 0 && hasPatternStubs()) {
                codeState(patternMethod, 1);
                for (int i = 0; i < 1000 && (codeState(patternMethod, -1) & 0x20000) == 0; ++i)
                    Thread.sleep(10);
                check((codeState(patternMethod, -1) & 0x20000) != 0);
                System.out.println("PATTERN_STUB_READY");
            }
            compile(hotMethod, 2, 1);
            compile(osrMethod, 1, 1);
            compile(osrMethod, 2, 2);
            compile(osrMethod, 0, 0x10000);
            long state = codeState(osrMethod, -2);
            System.out.println("COMPILED_STATE=" + state);
            // Ordinary + OSR code and seeded ART CHA/processed-zombie records.
            check((state & 0xffff) >= 2 && (state & 0x10000) != 0);
            check((state >>> 32) != 0);
        }
        AtomicReference<Throwable> error = new AtomicReference<>();
        Thread pending = new Thread(() -> {
            try { check(active(7) == 8); } catch (Throwable t) { error.set(t); }
        });
        pending.start();
        check(entered.await(5, TimeUnit.SECONDS));
        if (jit) holdJit();
        System.out.println("HOOK_FIXTURE_READY pid=" + processId());
        awaitPhase(args[2], 4);
        if (jit) releaseJit();
        System.out.println("JIT_IDLE_READY");
        awaitPhase(args[2], 1);
        check(Modifier.isNative(AdmissionMain.class.getDeclaredMethod("cold", int.class).getModifiers()));
        check(Modifier.isNative(AdmissionMain.class.getDeclaredMethod("hot", int.class).getModifiers()));
        check(Modifier.isNative(AdmissionMain.class.getDeclaredMethod("osr", int.class).getModifiers()));
        check(!Modifier.isNative(AdmissionMain.class.getDeclaredMethod("active", int.class).getModifiers()));
        check(lazyInitialized && Lazy.cold(3) == 28);
        check(codeState(hotMethod, -1) == 0 && codeState(osrMethod, -1) == 0);
        collectCode(); // exercise zombie/CHA cleanup after header reclamation
        receiver = new Derived(); // invalidate the old single-implementation assumption
        check(cold(3) == 28 && hot(3) == 52 && osr(3) == 182 && pattern(3) == 2);
        for (int i = 0; i < 10000; ++i) {
            check(cold(i) == (i + 11) * 2);
            check(hot(i) == (i + 10) * 4 && osr(5) == 240);
            if (i % 1000 == 0) { System.gc(); collectCode(); }
        }
        release.countDown();
        pending.join(5000);
        check(!pending.isAlive() && error.get() == null);
        System.out.println("ACTIVE_FRAMES_EXITED_OK");
        awaitPhase(args[2], 2);
        check(active(5) == 32 && cold(5) == 6 && hot(5) == 60 && osr(5) == 240);
        check(Modifier.isNative(AdmissionMain.class.getDeclaredMethod("cold", int.class).getModifiers()));
        System.out.println("LOGICAL_DISABLE_OK");
        awaitPhase(args[2], 3);
        for (int i = 0; i < 10000; ++i) {
            check(cold(i) == i + 1 && active(i) == i + 1 && hot(i) == i * 2);
            check(osr(5) == 15 && Lazy.cold(i) == i + 1 && pattern(i) == 1);
            if (i % 1000 == 0) System.gc();
        }
        System.out.println("ALL_ADMISSION_TESTS_PASS");
    }
}
