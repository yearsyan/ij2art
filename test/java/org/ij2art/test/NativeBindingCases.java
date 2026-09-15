package org.ij2art.test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.concurrent.atomic.AtomicReference;

public final class NativeBindingCases {
    public native int instance(int x);
    public static native int statik(int x);
    public synchronized native int syncInstance(int x);
    public static synchronized native int syncStatic(int x);
    public native int missing(int x);
    public int managed(int x) { return 7 + x; }
    public static native int control(int x);
    private static final NativeBindingCases receiver = new NativeBindingCases();
    private static Method[] methods;
    public static final class Driver {
        public static native int bind(int action);
    }
    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }
    public static Method[] prepare() throws Exception {
        String[] names = {"instance", "statik", "syncInstance", "syncStatic", "missing", "managed"};
        methods = new Method[names.length];
        for (int i = 0; i < names.length; ++i) methods[i] = NativeBindingCases.class.getDeclaredMethod(names[i], int.class);
        for (int i = 0; i < 100; ++i) run(false, 7, false);
        return methods;
    }
    private static int invoke(int i, int x) throws Throwable {
        try { return (Integer) methods[i].invoke(Modifier.isStatic(methods[i].getModifiers()) ? null : receiver, x); }
        catch (InvocationTargetException error) { throw error.getCause(); }
    }
    public static int nativeBody(Object lock, int x, int base, boolean sync) {
        if (sync) check(Thread.holdsLock(lock), "native original lost monitor");
        if (x == -1) throw new IllegalStateException("native-original");
        return base + x;
    }
    public static void run(boolean hooked, int base, boolean unbound) throws Exception {
        try {
            for (int i = 0; i < methods.length; ++i) {
                if (hooked) check(invoke(i, 1) == 1001, "skip must survive unregister: " + i);
                if (unbound && i == 4) {
                    try { invoke(i, 5); throw new AssertionError("missing symbol must throw"); }
                    catch (UnsatisfiedLinkError expected) { /* hook still calls the unbound backup */ }
                    continue;
                }
                int expected = (i == 5 ? 7 : base) + 5 + (hooked ? 1000 : 0);
                check(invoke(i, 5) == expected, "binding/original mismatch: " + i + " expected " + expected);
                if (i < 5) {
                    try { invoke(i, -1); throw new AssertionError("original exception lost"); }
                    catch (IllegalStateException expectedError) {
                        check("native-original".equals(expectedError.getMessage()), "wrong native exception");
                    }
                }
            }
            check(control(5) == base + 5, "unhooked control binding changed");
        } catch (Exception error) { throw error; }
        catch (Error error) { throw error; }
        catch (Throwable error) { throw new AssertionError(error); }
    }
    public static void race(boolean hooked) throws Exception {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread[] threads = new Thread[4];
        for (int i = 0; i < threads.length; ++i) {
            threads[i] = new Thread(() -> {
                try {
                    for (int n = 0; n < 400; ++n) for (int j = 0; j < 5; ++j) {
                        int value = invoke(j, 5) - (hooked ? 1000 : 0);
                        check(value == 12 || value == 75, "racing registration bypassed hook: " + value);
                    }
                } catch (Throwable error) { failure.compareAndSet(null, error); }
            }, "jni-binding-race");
            threads[i].setDaemon(true);
            threads[i].start();
        }
        for (int i = 0; i < 200; ++i) check(Driver.bind(i & 1) == 1, "register failed");
        for (Thread thread : threads) {
            thread.join(15000);
            check(!thread.isAlive(), "binding race timed out");
        }
        if (failure.get() != null) throw new AssertionError(failure.get());
        check(Driver.bind(1) == 1, "final register failed");
        run(hooked, 70, false);
    }
    public static void watch() {
        Thread worker = new Thread(() -> {
            try {
                for (int seq = 1; ; ++seq) {
                    check(Driver.bind(0) == 1, "watch register"); run(false, 7, false);
                    check(Driver.bind(1) == 1, "watch re-register"); run(false, 70, false);
                    check(Driver.bind(2) == 1, "watch unregister"); run(false, 700, true);
                    System.out.println("NATIVE_BINDING_WATCH PASS seq=" + seq);
                    Thread.sleep(150);
                }
            } catch (Throwable error) {
                error.printStackTrace();
                System.out.println("NATIVE_BINDING_WATCH FAIL " + error);
            }
        }, "jni-binding-watch");
        worker.setDaemon(true);
        worker.start();
    }
}
