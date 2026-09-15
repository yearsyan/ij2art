package org.ij2art.test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Real monitor tests; reflection keeps ENTRY_ONLY calls at the target entry. */
public final class SynchronizedCases {
    private static Method[] methods;
    private static final AtomicInteger originals = new AtomicInteger();
    private static volatile boolean waiting, signalled, holding, entered, finished;
    private static Thread heldThread, drainingThread;
    private static final AtomicReference<Throwable> backgroundError = new AtomicReference<>();
    private static final SynchronizedCases drainingObject = new SynchronizedCases();

    public synchronized int instance(int mode) throws Throwable { return body(this, mode); }
    public static synchronized int staticValue(int mode) throws Throwable {
        return body(SynchronizedCases.class, mode);
    }
    public synchronized int blocking(int mode) throws Throwable {
        if (holding) {
            entered = true;
            long deadline = System.nanoTime() + 60_000_000_000L;
            while (holding) {
                check(System.nanoTime() < deadline, "old frame timeout");
                Thread.sleep(5);
            }
        }
        return body(this, mode);
    }
    public synchronized native int nativeInstance(int mode) throws Throwable;
    public static synchronized native int nativeStatic(int mode) throws Throwable;

    public static Method[] prepare() throws Exception {
        methods = new Method[5];
        String[] names = {"instance", "staticValue", "blocking", "nativeInstance", "nativeStatic"};
        for (int i = 0; i < names.length; i++)
            methods[i] = SynchronizedCases.class.getDeclaredMethod(names[i], int.class);
        return methods;
    }

    public static int body(Object lock, int mode) throws Throwable {
        check(Thread.holdsLock(lock), "original does not own the target monitor");
        originals.incrementAndGet();
        if (mode == 3) throw new IllegalArgumentException("sync-original");
        if (mode == 5) awaitSignal(lock);
        if (mode == 8) {
            int index = lock == SynchronizedCases.class ? 1 : 0;
            return invoke(methods[index], index == 1 ? null : lock, 0) + 3;
        }
        return 7;
    }

    // Also called from the replacement to test wait/notify without an original frame.
    public static void awaitSignal(Object lock) throws InterruptedException {
        check(Thread.holdsLock(lock), "wait without target monitor");
        waiting = true;
        long deadline = System.nanoTime() + 10_000_000_000L;
        while (!signalled) {
            check(System.nanoTime() < deadline, "notification timeout");
            lock.wait(100);
        }
        check(Thread.holdsLock(lock), "wait did not reacquire monitor");
        waiting = false;
    }

    private static int invoke(Method method, Object receiver, int mode) throws Throwable {
        try { return (Integer) method.invoke(receiver, mode); }
        catch (InvocationTargetException error) { throw error.getCause(); }
    }
    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }
    private static void join(Thread thread) throws Throwable {
        thread.join(12000);
        check(!thread.isAlive(), "thread did not finish: " + thread.getName());
        Throwable error = backgroundError.getAndSet(null);
        if (error != null) throw error;
    }
    private static Thread start(String name, Runnable work) {
        Thread thread = new Thread(work, name);
        thread.setDaemon(true);
        thread.start();
        return thread;
    }
    private static void notifyWaiter(Object lock) throws InterruptedException {
        long deadline = System.nanoTime() + 10_000_000_000L;
        while (!waiting) {
            check(System.nanoTime() < deadline, "waiter did not start");
            Thread.sleep(1);
        }
        synchronized (lock) { signalled = true; lock.notifyAll(); }
    }
    private static void waitCase(Method method, Object receiver, Object lock, int mode, boolean hooked)
            throws Throwable {
        waiting = signalled = false;
        Thread worker = start("sync-wait", () -> {
            try { check(invoke(method, receiver, mode) == (hooked ? 107 : 7), "wait result"); }
            catch (Throwable error) { backgroundError.set(error); }
        });
        notifyWaiter(lock);
        join(worker);
    }

    public static void run(boolean hooked) throws Throwable {
        for (int i = 0; i < methods.length; i++) {
            Method method = methods[i];
            boolean enabled = hooked;
            Object receiver = Modifier.isStatic(method.getModifiers()) ? null : new SynchronizedCases();
            Object lock = receiver == null ? SynchronizedCases.class : receiver;
            // Android reflection normalizes DeclaredSynchronized, while D8
            // emits only the native Synchronized bit for these JNI methods.
            // The native fixture checks both raw bits on target and backup.
            if (i < 3) check(Modifier.isSynchronized(method.getModifiers()), "lost synchronized reflection flag");
            for (int mode = 0; mode <= 2; mode++) {
                int before = originals.get();
                int result = invoke(method, receiver, mode);
                int expected = !enabled ? 7 : mode == 1 ? 101 : mode == 2 ? 114 : 107;
                check(result == expected, method + " result " + result);
                check(originals.get() - before == (!enabled ? 1 : mode == 1 ? 0 : mode == 2 ? 2 : 1),
                      "skip/repeated original count");
            }
            // Existing same-hook recursion protection bypasses the callback;
            // another hooked method on the same monitor gets its own callback.
            boolean innerHooked = hooked && !(enabled && i < 2);
            int reentered = invoke(method, receiver, 8);
            check(reentered == 10 + (enabled ? 100 : 0) + (innerHooked ? 100 : 0),
                  method + " reentry result " + reentered);
            for (int mode : new int[]{3, 4, 9}) {
                if (!enabled && mode != 3) continue;
                try { invoke(method, receiver, mode); throw new AssertionError("expected exception"); }
                catch (IllegalArgumentException error) { check(mode == 3 && error.getMessage().equals("sync-original"), "original exception"); }
                catch (IllegalStateException error) { check(mode == 4 && error.getMessage().equals("sync-handler"), "handler exception"); }
                catch (ClassCastException error) { check(mode == 9, "result type exception"); }
                Thread probe = start("sync-unlock", () -> { synchronized (lock) { /* must be acquirable */ } });
                join(probe);
            }
            waitCase(method, receiver, lock, 5, enabled);
            if (enabled) waitCase(method, receiver, lock, 6, true);
            AtomicInteger completed = new AtomicInteger();
            Thread[] workers = new Thread[4];
            for (int w = 0; w < workers.length; w++) workers[w] = start("sync-contention", () -> {
                try {
                    for (int n = 0; n < 50; n++) {
                        check(invoke(method, receiver, 0) == (enabled ? 107 : 7), "contended call");
                        completed.incrementAndGet();
                    }
                } catch (Throwable error) { backgroundError.set(error); }
            });
            for (Thread worker : workers) join(worker);
            check(completed.get() == 200, "missing contended calls");
        }
        System.gc();
    }

    public static int block(int action) throws Throwable {
        if (action == 0) {
            holding = true; entered = finished = false;
            heldThread = start("sync-old-frame", () -> {
                try { invoke(methods[2], new SynchronizedCases(), 0); }
                catch (Throwable error) { backgroundError.set(error); }
                finally { finished = true; }
            });
        }
        if (action == 1) { holding = false; join(heldThread); }
        return finished ? 2 : entered ? 1 : 0;
    }

    public static int drain(int action) throws Throwable {
        if (action == 0) {
            waiting = signalled = false;
            drainingThread = start("sync-drain", () -> {
                try { check(invoke(methods[0], drainingObject, 5) == 107, "draining original"); }
                catch (Throwable error) { backgroundError.set(error); }
            });
        }
        if (action == 1) { notifyWaiter(drainingObject); join(drainingThread); return 2; }
        return waiting ? 1 : 0;
    }
}
