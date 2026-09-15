package org.ij2art.test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.concurrent.atomic.AtomicReference;

public final class HookUpdateCases {
    public static int staticValue(int x) { return body(x); }
    public int instanceValue(int x) { return body(x); }
    public synchronized int syncValue(int x) {
        check(Thread.holdsLock(this), "original lost monitor"); return body(x);
    }
    public native int nativeValue(int x);
    private static final HookUpdateCases receiver = new HookUpdateCases();
    private static Method[] methods;
    private static final Object lock = new Object();
    private static boolean waiting, release;
    private static volatile boolean racing;
    private static Thread blocked;
    private static Thread[] racers;
    private static int blockedResult;
    private static final AtomicReference<Throwable> failure = new AtomicReference<>();
    private static void check(boolean ok, String text) { if (!ok) throw new AssertionError(text); }
    public static Method[] prepare() throws Throwable {
        String[] names = {"staticValue", "instanceValue", "syncValue", "nativeValue"};
        methods = new Method[names.length];
        for (int i = 0; i < names.length; ++i) methods[i] = HookUpdateCases.class.getDeclaredMethod(names[i], int.class);
        for (int n = 0; n < 100; ++n) for (int i = 0; i < methods.length; ++i) probe(i, 5, 15);
        return methods;
    }
    public static int body(int x) {
        if (x == 97) synchronized (lock) {
            waiting = true; lock.notifyAll();
            long until = System.nanoTime() + 90_000_000_000L;
            while (!release) {
                check(System.nanoTime() < until, "blocked original timed out");
                try { lock.wait(100); } catch (InterruptedException error) { throw new AssertionError(error); }
            }
        }
        if (x == 98) throw new IllegalStateException("original-error");
        return x + 10;
    }
    private static int invoke(int index, int x) throws Throwable {
        try { return (Integer) methods[index].invoke(Modifier.isStatic(methods[index].getModifiers()) ? null : receiver, x); }
        catch (InvocationTargetException error) { throw error.getCause(); }
    }
    public static void probe(int index, int x, int expected) throws Throwable {
        if (expected == -1 || expected == -2 || expected == -3) {
            try { invoke(index, x); throw new AssertionError("expected exception"); }
            catch (IllegalStateException error) {
                check(expected == -1 && "original-error".equals(error.getMessage()), "wrong original exception");
            } catch (IllegalArgumentException error) {
                check(expected == -2 && "replacement-error".equals(error.getMessage()), "wrong replacement exception");
            } catch (ClassCastException error) { check(expected == -3, "wrong result exception"); }
        } else {
            int actual = invoke(index, x);
            check(actual == expected, "method " + index + " expected " + expected + " got " + actual);
        }
    }
    public static int block(int action, int index) throws Exception {
        if (action == 0) {
            failure.set(null);
            synchronized (lock) { waiting = false; release = false; }
            blocked = new Thread(() -> {
                try { blockedResult = invoke(index, 97); }
                catch (Throwable error) { failure.set(error); }
            }, "hook-update-old-call");
            blocked.setDaemon(true); blocked.start(); return 1;
        }
        if (action == 1) {
            synchronized (lock) { release = true; lock.notifyAll(); }
            blocked.join(15000);
            check(!blocked.isAlive(), "old callback stuck");
            if (failure.get() != null) throw new AssertionError(failure.get());
            check(blockedResult == 240, "old version/original/recursion changed: " + blockedResult);
            return 1;
        }
        synchronized (lock) { return waiting ? 1 : 0; }
    }
    public static void race(boolean start) throws Exception {
        if (!start) {
            racing = false;
            for (Thread thread : racers) { thread.join(15000); check(!thread.isAlive(), "race stuck"); }
            if (failure.get() != null) throw new AssertionError(failure.get());
            return;
        }
        failure.set(null); racing = true;
        racers = new Thread[4];
        for (int i = 0; i < racers.length; ++i) {
            racers[i] = new Thread(() -> {
                try {
                    while (racing) for (int j = 1; j < 4; ++j) {
                        int value = invoke(j, 5);
                        check(value == 215 || value == 315, "mixed callback version: " + value);
                    }
                } catch (Throwable error) { failure.compareAndSet(null, error); racing = false; }
            }, "hook-update-racer");
            racers[i].setDaemon(true); racers[i].start();
        }
    }
}
