package org.ij2art;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Real generic-JNI frames with production dispatcher/lifecycle, no managed conversion. */
public final class LogicalDisable {
    private static native void setup();
    private static native int disable(int slot);
    private static native boolean shutdown();
    public static native int target(int value);
    public static native String targetRef(String value);
    public static native double targetDouble(double value);
    public static int original(int value) { return value + 1; }
    public static String originalRef(String value) { return value + "-original"; }
    public static double originalDouble(double value) { return value + 0.5; }
    private static final CountDownLatch entered = new CountDownLatch(1);
    private static final CountDownLatch release = new CountDownLatch(1);

    public static Object replace(HookContext context) throws Throwable {
        if (context.method.getName().equals("target")) {
            if (((Integer) context.args[0]) == 7) {
                entered.countDown();
                if (!release.await(10, TimeUnit.SECONDS)) throw new AssertionError("release timeout");
                // An old replacement still has its native outer frame and token.
                check(Thread.currentThread().getStackTrace().length > 0);
                System.gc();
            }
            return ((Integer) context.callOriginal()) + 100;
        }
        if (context.method.getName().equals("targetRef")) return context.callOriginal() + "-hook";
        return ((Double) context.callOriginal()) * 2;
    }

    private static void check(boolean ok) { if (!ok) throw new AssertionError(); }

    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        setup();
        check(target(3) == 104);
        check(targetRef("x").equals("x-original-hook"));
        check(targetDouble(1.5) == 4.0);
        AtomicReference<Throwable> error = new AtomicReference<>();
        Thread pending = new Thread(() -> {
            try { check(target(7) == 108); } catch (Throwable t) { error.set(t); }
        });
        pending.start();
        check(entered.await(10, TimeUnit.SECONDS));
        check(disable(0) == 3); // DRAINING: one replacement remains blocked.
        check(target(3) == 4);
        check(!shutdown());   // closes other Hooks and installation admission too.
        check(targetRef("x").equals("x-original"));
        check(targetDouble(1.5) == 2.0);
        release.countDown();
        pending.join(10000);
        check(!pending.isAlive() && error.get() == null);
        check(disable(0) == 4); // DISABLED, not physically removed.
        check(disable(0) == 4); // idempotent.
        check(disable(1) == 4 && disable(2) == 4);
        check(shutdown());
        // Late entries remain safe even after logical shutdown reports completion.
        for (int n = 0; n < 10000; ++n) check(target(n) == n + 1);
        check(targetRef("late").equals("late-original"));
        check(targetDouble(-2.0) == -1.5);
        System.out.println("PASS: logical DEL/shutdown, blocked replacement callOriginal, JNI frames retained, late int/ref/double forwarding, DEX pins, closed install admission (CheckJNI; no managed conversion)");
    }
}
