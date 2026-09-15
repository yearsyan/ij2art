package org.ij2art.test;

import java.nio.file.Files;
import java.nio.file.Paths;

/** Phase-file driven acceptance fixture for the replacement backend.
 *  The runner advances phases by writing an integer into the phase file after
 *  each CLI action; every phase asserts exact observable behavior.
 *
 *  Requirements of this controlled environment (corresponding to the "call coverage
 *  boundary" section of the design document): FULL does not yet cover direct calls made
 *  by compiled callers, so this fixture must guarantee two things. (1) All assertion call
 *  sites stay interpreted, which means main contains no hot loop and the only stress loop
 *  lives in a separate method. (2) The targets are not compiled before installation, which
 *  means hammer starts only after all the relevant Hooks have been installed. Otherwise a
 *  compiled caller would bypass the rewritten entry point and the test would be a matter
 *  of luck. */
public final class HookMain {
    private static native void start(String payload, ClassLoader loader);

    private static String phaseFile;
    private static volatile boolean stopWorkers;

    public static int target1(int value) { return value + 1; }
    public static int target2(int value) { return value + 1; }
    public static int target3(int value) {
        if (value < 0) throw new IllegalArgumentException("original exception");
        return value + 1;
    }
    private int base = 7;
    public int target4(int value) { return value * 2 + base; }   // Virtual method: verifies the CallNonvirtual recursion guard
    private int targetPrivate(int value) { return value * 3; }   // Private instance method
    public static synchronized int targetSync(int value) { return value; }
    public static long targetLong(long v) { return v + 10000000000L; }
    public static String targetRef(String s, int n) { return s + n; }
    public static double targetMix(int a, double b, long c, float d, Object e,
                                   int f, int g, int h, int i, double j) {
        return a + b + c + d + (e == null ? 0 : 1) + f + g + h + i + j;
    }

    private static void fail(String what) {
        System.out.println("HOOK_TEST_FAIL " + what);
        Runtime.getRuntime().halt(1);
    }
    private static void expect(boolean ok, String what) { if (!ok) fail(what); }

    private static int phase() {
        try {
            return Integer.parseInt(new String(Files.readAllBytes(Paths.get(phaseFile))).trim());
        } catch (Throwable ignored) { return -1; }
    }
    private static void awaitPhase(int want) throws Exception {
        while (phase() != want) Thread.sleep(40);
    }

    // Concurrency hammer: a call that hits a hook may only produce two values (8 from the
    // original implementation, or 42 from skip); anything else counts as a failure.
    // See main for when it is started: it must come after target2/target3 have been installed,
    // which ensures the targets are rewritten before they are compiled.
    private static void hammer() {
        for (int n = 0; n < 4; n++) {
            Thread t = new Thread(() -> {
                while (!stopWorkers) {
                    int v = target2(7);
                    if (v != 8 && v != 42) fail("target2 unexpected " + v);
                    if (target3(5) != 6) fail("target3 changed semantics");
                }
            }, "hammer-" + n);
            t.setDaemon(true);
            t.start();
        }
        Thread gc = new Thread(() -> {
            while (!stopWorkers) {
                byte[][] batch = new byte[64][];
                for (int i = 0; i < batch.length; i++) batch[i] = new byte[4096];
            }
        }, "gc-churn");
        gc.setDaemon(true);
        gc.start();
    }

    // The stress loop is kept in its own method on purpose: it gets JIT-compiled, which lets us
    // verify that "a compiled caller still enters the Hook through the entry point" (hook1 is
    // installed before compilation, so direct calls embed the captured entry address). If the
    // loop lived in main, it would make main itself hot and turn the assertion call sites in
    // later phases into direct calls that bypass the entry point.
    private static void stressTarget1() {
        for (int i = 0; i < 30000; i++) expect(target1(3) == 28, "hooked target1 it=" + i);
    }

    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        start(args[1], HookMain.class.getClassLoader());
        phaseFile = args[2];
        System.out.println("HOOK_FIXTURE_READY pid=" + android.os.Process.myPid());

        awaitPhase(0);                                   // baseline: only a few calls, so it stays interpreted
        for (int i = 0; i < 50; i++) expect(target1(3) == 4, "baseline target1");
        System.out.println("PHASE0_OK");

        awaitPhase(1);                                   // replace: (3+10+1)*2 = 28, including JIT warmup
        stressTarget1();
        System.out.println("PHASE1_OK");

        awaitPhase(2);                                   // skip: the original implementation is not called
        expect(target2(7) == 42, "skip target2");
        System.out.println("PHASE2_OK");

        awaitPhase(3);                                   // passthrough: the original exception must propagate unchanged
        expect(target3(5) == 6, "passthrough value");
        try {
            target3(-1);
            fail("original exception missing");
        } catch (IllegalArgumentException e) {
            expect("original exception".equals(e.getMessage()), "exception identity");
        }
        System.out.println("PHASE3_OK");
        hammer();  // all three Hooks are installed: the targets now carry kAccCompileDontBother, so they are not compiled

        awaitPhase(4);                                   // instance method: the result is callOriginal + 100
        HookMain self = new HookMain();
        expect(self.target4(5) == 117, "virtual instance target4");
        expect(self.targetPrivate(5) == 115, "private instance targetPrivate");
        System.out.println("PHASE4_OK");

        awaitPhase(5);                                   // delete hook1: the original implementation is restored
        expect(target1(3) == 4, "restored target1");
        System.out.println("PHASE5_OK");

        awaitPhase(6);                                   // concurrent add/del flooding from the runner, while the hammer threads assert
        System.out.println("PHASE6_OK");

        awaitPhase(7);                                   // the flooding has ended and hook2 has been deleted
        expect(target2(7) == 8, "restored target2");
        System.out.println("PHASE7_OK");

        awaitPhase(8);                                   // wide types, long, reference and stack-overflow arguments
        expect(targetLong(5) == 10000000005L, "long passthrough");
        expect("ab3!".equals(targetRef("ab", 3)), "ref replace");
        expect(targetMix(1, 2.0, 3, 4.0f, "x", 5, 6, 7, 8, 9.0) == 46.0, "mix passthrough");
        System.out.println("PHASE8_OK");

        awaitPhase(9);                                   // everything is restored after shutdown
        expect(target2(7) == 8, "post-shutdown target2");
        expect(target3(5) == 6, "post-shutdown target3");
        expect("ab3".equals(targetRef("ab", 3)), "post-shutdown ref");
        stopWorkers = true;
        System.out.println("ALL_HOOK_TESTS_PASS");
    }
}
