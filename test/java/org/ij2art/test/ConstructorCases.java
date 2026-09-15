package org.ij2art.test;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

/** Shared by the CheckJNI runner and the dexopt'ed APK. */
public final class ConstructorCases {
    public static volatile int noise;
    public static int baseCalls, childCalls, zeroCalls, throwingCalls;
    public static volatile boolean entered, release, finished;
    private static Constructor<?>[] constructors;

    public static class Base {
        public final int base;
        public Base(int value) {
            base = value;
            baseCalls++;
            // Keep this constructor larger than ART's inlining budget. The
            // this/super tests intentionally exercise ENTRY_ONLY dispatch.
            noise = (noise * 31) ^ (value + 0);
            noise = (noise * 31) ^ (value + 1);
            noise = (noise * 31) ^ (value + 2);
            noise = (noise * 31) ^ (value + 3);
            noise = (noise * 31) ^ (value + 4);
            noise = (noise * 31) ^ (value + 5);
            noise = (noise * 31) ^ (value + 6);
            noise = (noise * 31) ^ (value + 7);
            noise = (noise * 31) ^ (value + 8);
            noise = (noise * 31) ^ (value + 9);
            noise = (noise * 31) ^ (value + 10);
            noise = (noise * 31) ^ (value + 11);
            noise = (noise * 31) ^ (value + 12);
            noise = (noise * 31) ^ (value + 13);
            noise = (noise * 31) ^ (value + 14);
            noise = (noise * 31) ^ (value + 15);
            noise = (noise * 31) ^ (value + 16);
            noise = (noise * 31) ^ (value + 17);
            noise = (noise * 31) ^ (value + 18);
            noise = (noise * 31) ^ (value + 19);
            noise = (noise * 31) ^ (value + 20);
            noise = (noise * 31) ^ (value + 21);
            noise = (noise * 31) ^ (value + 22);
            noise = (noise * 31) ^ (value + 23);
            noise = (noise * 31) ^ (value + 24);
            noise = (noise * 31) ^ (value + 25);
            noise = (noise * 31) ^ (value + 26);
            noise = (noise * 31) ^ (value + 27);
            noise = (noise * 31) ^ (value + 28);
            noise = (noise * 31) ^ (value + 29);
            noise = (noise * 31) ^ (value + 30);
            noise = (noise * 31) ^ (value + 31);
            noise = (noise * 31) ^ (value + 32);
            noise = (noise * 31) ^ (value + 33);
            noise = (noise * 31) ^ (value + 34);
            noise = (noise * 31) ^ (value + 35);
            noise = (noise * 31) ^ (value + 36);
            noise = (noise * 31) ^ (value + 37);
            noise = (noise * 31) ^ (value + 38);
            noise = (noise * 31) ^ (value + 39);
            noise = (noise * 31) ^ (value + 40);
            noise = (noise * 31) ^ (value + 41);
            noise = (noise * 31) ^ (value + 42);
            noise = (noise * 31) ^ (value + 43);
            noise = (noise * 31) ^ (value + 44);
            noise = (noise * 31) ^ (value + 45);
            noise = (noise * 31) ^ (value + 46);
            noise = (noise * 31) ^ (value + 47);
        }
    }
    public static final class Child extends Base {
        public final int value;
        public final String name;
        public int after;
        public Child() { this(3, "default"); zeroCalls++; }
        private Child(int value, String name) {
            super(value + 1);
            this.value = value;
            this.name = name;
            childCalls++;
            noise = (noise * 31) ^ (value + 0);
            noise = (noise * 31) ^ (value + 1);
            noise = (noise * 31) ^ (value + 2);
            noise = (noise * 31) ^ (value + 3);
            noise = (noise * 31) ^ (value + 4);
            noise = (noise * 31) ^ (value + 5);
            noise = (noise * 31) ^ (value + 6);
            noise = (noise * 31) ^ (value + 7);
            noise = (noise * 31) ^ (value + 8);
            noise = (noise * 31) ^ (value + 9);
            noise = (noise * 31) ^ (value + 10);
            noise = (noise * 31) ^ (value + 11);
            noise = (noise * 31) ^ (value + 12);
            noise = (noise * 31) ^ (value + 13);
            noise = (noise * 31) ^ (value + 14);
            noise = (noise * 31) ^ (value + 15);
            noise = (noise * 31) ^ (value + 16);
            noise = (noise * 31) ^ (value + 17);
            noise = (noise * 31) ^ (value + 18);
            noise = (noise * 31) ^ (value + 19);
            noise = (noise * 31) ^ (value + 20);
            noise = (noise * 31) ^ (value + 21);
            noise = (noise * 31) ^ (value + 22);
            noise = (noise * 31) ^ (value + 23);
            noise = (noise * 31) ^ (value + 24);
            noise = (noise * 31) ^ (value + 25);
            noise = (noise * 31) ^ (value + 26);
            noise = (noise * 31) ^ (value + 27);
            noise = (noise * 31) ^ (value + 28);
            noise = (noise * 31) ^ (value + 29);
            noise = (noise * 31) ^ (value + 30);
            noise = (noise * 31) ^ (value + 31);
            noise = (noise * 31) ^ (value + 32);
            noise = (noise * 31) ^ (value + 33);
            noise = (noise * 31) ^ (value + 34);
            noise = (noise * 31) ^ (value + 35);
            noise = (noise * 31) ^ (value + 36);
            noise = (noise * 31) ^ (value + 37);
            noise = (noise * 31) ^ (value + 38);
            noise = (noise * 31) ^ (value + 39);
            noise = (noise * 31) ^ (value + 40);
            noise = (noise * 31) ^ (value + 41);
            noise = (noise * 31) ^ (value + 42);
            noise = (noise * 31) ^ (value + 43);
            noise = (noise * 31) ^ (value + 44);
            noise = (noise * 31) ^ (value + 45);
            noise = (noise * 31) ^ (value + 46);
            noise = (noise * 31) ^ (value + 47);
        }
    }
    public static final class Throwing {
        public final int value;
        public Throwing(int value) {
            throwingCalls++;
            if (value < 0) throw new IllegalArgumentException("ctor-original");
            this.value = value;
        }
    }
    public static final class Blocking {
        public final int value;
        public Blocking(int value) {
            entered = true;
            long deadline = System.nanoTime() + 120_000_000_000L;
            while (!release) {
                if (System.nanoTime() > deadline) throw new AssertionError("ctor release timeout");
                try { Thread.sleep(10); } catch (InterruptedException e) { throw new AssertionError(e); }
            }
            this.value = value;
        }
    }
    public static Constructor<?>[] prepare() throws Exception {
        constructors = new Constructor<?>[]{Base.class.getDeclaredConstructor(int.class),
            Child.class.getDeclaredConstructor(int.class, String.class), Child.class.getDeclaredConstructor(),
            Throwing.class.getDeclaredConstructor(int.class), Blocking.class.getDeclaredConstructor(int.class)};
        for (Constructor<?> c : constructors) {
            c.setAccessible(true);
            Class.forName(c.getDeclaringClass().getName(), true, c.getDeclaringClass().getClassLoader());
        }
        return constructors;
    }
    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
    public static void run(boolean hooked) throws Exception {
        baseCalls = childCalls = zeroCalls = throwingCalls = 0;
        Base base = (Base) constructors[0].newInstance(1);
        check(base.base == (hooked ? 101 : 1), "base initialization");
        Child child = (Child) constructors[1].newInstance(2, "x");
        check(child.value == (hooked ? 12 : 2), "private constructor arguments");
        check(child.base == (hooked ? 113 : 3), "super constructor");
        check(child.name.equals(hooked ? "x!" : "x"), "reference argument");
        check(child.after == (hooked ? 7 : 0), "same receiver after original");
        Child zero = (Child) constructors[2].newInstance();
        check(zero.value == (hooked ? 13 : 3), "this constructor");
        check(zero.base == (hooked ? 114 : 4), "this/super chain");
        check(zero.after == (hooked ? 16 : 0), "nested replacement contexts");
        check(baseCalls == 3 && childCalls == 2 && zeroCalls == 1, "original ran once");
        Throwing normal = (Throwing) constructors[3].newInstance(5);
        check(normal.value == 5, "throwing constructor normal path");
        try { constructors[3].newInstance(-1); throw new AssertionError("original exception lost"); }
        catch (InvocationTargetException e) {
            check(e.getCause() instanceof IllegalArgumentException &&
                  "ctor-original".equals(e.getCause().getMessage()), "original exception identity");
        }
        if (hooked) {
            try { constructors[3].newInstance(-2); throw new AssertionError("handler exception lost"); }
            catch (InvocationTargetException e) {
                check(e.getCause() instanceof IllegalStateException &&
                      "ctor-handler".equals(e.getCause().getMessage()), "handler exception");
            }
            try { constructors[3].newInstance(99); throw new AssertionError("non-void result accepted"); }
            catch (InvocationTargetException e) { check(e.getCause() instanceof ClassCastException, "void result"); }
        }
        check(throwingCalls == 2, "throwing constructor invocation count");
        if (finished) {
            Blocking block = (Blocking) constructors[4].newInstance(1);
            check(block.value == (hooked ? 6 : 1), "previously active constructor");
        }
        System.gc();
    }
    public static void startBlock() {
        new Thread(() -> {
            try {
                constructors[4].newInstance(1);
                finished = true;
            } catch (Throwable e) { throw new AssertionError(e); }
        }, "constructor-old-frame").start();
    }
    public static int block(int action) {
        if (action == 0) startBlock();
        if (action == 1) release = true;
        return finished ? 2 : entered ? 1 : 0;
    }
}
