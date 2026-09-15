package org.ij2art.test;

import android.os.Looper;
import java.io.File;

public final class JavaCallCases {
    private static int counter;
    public static boolean onMain() { return Looper.myLooper() == Looper.getMainLooper() && Looper.myLooper() != null; }
    public static String threadName() { return Thread.currentThread().getName(); }
    public static String contextLoader() { return Thread.currentThread().getContextClassLoader().getClass().getName(); }
    public static synchronized int increment() { return ++counter; }
    public static synchronized int count() { return counter; }
    public static String pick(int value) { return "int:" + value; }
    public static String pick(long value) { return "long:" + value; }
    public static long longValue(long value) { return value; }
    public static String primitives(boolean z, byte b, short s, char c, int i, long j, float f, double d) {
        return z + ":" + b + ":" + s + ":" + c + ":" + i + ":" + j + ":" + f + ":" + d;
    }
    public static String nullString(String value) { return value == null ? "null" : value; }
    public static String text(String value) { return value; }
    public static int matrix(int[][] values) { return values[0][0] + values[1][1]; }
    public static String join(String[] values) { return values[0] + ":" + values[1]; }
    public static String reference(Object value) { return value.getClass().getName(); }
    private static String secret() { return "private-ok"; }
    public static void fail() { throw new IllegalStateException("fixture exception 中文 🌏"); }
    public static void badMessage() { throw new IllegalStateException() {
        @Override public String getMessage() { throw new IllegalStateException("message throws"); }
    }; }
    public static String huge() {
        StringBuilder value = new StringBuilder();
        for (int i = 0; i < 10000; ++i) value.append("🌏\n");
        return value.toString();
    }
    public static String waitForFile(String path) throws Exception {
        long deadline = System.nanoTime() + 60_000_000_000L;
        while (!new File(path).exists()) {
            if (System.nanoTime() > deadline) throw new IllegalStateException("fixture release timeout");
            Thread.sleep(10);
        }
        return "released";
    }
    private static volatile boolean restored;
    public static void checkRestoredLater() {
        restored = false;
        final ClassLoader previous = Thread.currentThread().getContextClassLoader();
        new android.os.Handler(Looper.getMainLooper()).post(() -> {
            // This runnable executes after the submitting main-thread Java job has restored its context.
            restored = Thread.currentThread().getContextClassLoader() != previous;
        });
    }
    public static boolean restoredMainLoader() { return restored; }
}
