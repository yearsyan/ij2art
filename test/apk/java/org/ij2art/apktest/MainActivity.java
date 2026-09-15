package org.ij2art.apktest;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import java.io.File;
import java.lang.reflect.Method;

/**
 * Real-App hook verification fixture. Not debuggable (kIndices), real
 * PathClassLoader over the APK dex, normal untrusted_app process.
 *
 * Workers log probe lines so a host script can assert hooked/original values:
 *   HOT n=<iters> sum=<sum> probe=<last add(x,3)>   direct loop (JIT inlines add)
 *   REF n=<iters> sum=<sum> probe=<last add(x,3)>   reflection call (never inlined)
 *   GRT n=<iters> probe=<last greet("w",n)>         reflection, reference args
 *   INS n=<iters> probe=<last instanceScale(x)>     reflection, instance method
 *   NAT n=<iters> probe=<last natMul(x,6)>          reflection call into bound native
 *   NATI n=<iters> probe=<last natInstanceScale(x)> reflection call into instance native
 *
 * Self-start path (Phase A): /data/local/tmp/ij2art-apktest-selfload exists ->
 * the app loads libpayload.so itself and signals runtime readiness, mirroring
 * what a cooperating App or a future production readiness hook would do.
 * Production path (Phase B): flag absent, payload comes from the carrier.
 */
public class MainActivity extends Activity {
    static final String TAG = "ij2art.apktest";
    static volatile boolean running = true;
    static Method addm, greetm, scalem, natm, natim;
    static {
        try {
            addm = MainActivity.class.getDeclaredMethod("add", int.class, int.class);
            greetm = MainActivity.class.getDeclaredMethod("greet", String.class, int.class);
            scalem = MainActivity.class.getDeclaredMethod("instanceScale", int.class);
            natm = MainActivity.class.getDeclaredMethod("natMul", int.class, int.class);
            natim = MainActivity.class.getDeclaredMethod("natInstanceScale", int.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ---- hook targets: keep bodies tiny and side-effect free ----
    public static int add(int a, int b) { return a + b; }
    public static String greet(String name, int n) { return name + "#" + n; }
    public int instanceScale(int v) { return v * 3; }
    public static int control(int v) { return v * 7 + 11; }
    public static int blocked(int v) { nativeHold(); return v + 1; }
    public static void startBlock() {
        new Thread(() -> {
            try {
                MainActivity.class.getDeclaredMethod("blocked", int.class).invoke(null, 1);
            } catch (Throwable t) { Log.e(TAG, "blocked worker died", t); }
        }, "aot-old-frame").start();
    }
    private static native void nativeHold();
    private static native long nativeCheck();
    // Bound-native hook targets (dlsym-resolved from libapkbridge on first call).
    public static native int natMul(int a, int b);
    public native int natInstanceScale(int v);
    // Never implemented: admission must reject it (unbound dlsym stub in data_).
    public static native int natUnbound(int v);

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        Log.i(TAG, "APK_FIXTURE_READY pid=" + android.os.Process.myPid()
                + " loader=" + MainActivity.class.getClassLoader());
        maybeSelfStart();
        startWorkers();
    }

    void maybeSelfStart() {
        try {
            String flag = getPackageName().equals("org.ij2art.aottest")
                    ? "/data/local/tmp/ij2art-aottest-selfload"
                    : "/data/local/tmp/ij2art-apktest-selfload";
            if (!new File(flag).exists()) {
                Log.i(TAG, "SELFLOAD off: expecting carrier-provided payload");
                return;
            }
            System.loadLibrary("apkbridge");
            String lib = getApplicationInfo().nativeLibraryDir + "/libpayload.so";
            nativeStart(lib, MainActivity.class.getClassLoader());
            Log.i(TAG, "SELFLOAD payload started from " + lib);
            startGuardWorker();
        } catch (Throwable t) {
            Log.e(TAG, "selfload failed", t);
        }
    }

    static void startGuardWorker() {
        new Thread(() -> {
            long seq = 0;
            while (running) {
                long result = nativeCheck();
                if (result != 0) Log.i(TAG, "AOT_GUARD result=" + result + " seq=" + (++seq));
                System.gc();
                try { Thread.sleep(500); } catch (InterruptedException e) { return; }
            }
        }, "aot-guard-gc").start();
    }

    static int probeValue(int x, int b) { return add(x, b); }

    void startWorkers() {
        final MainActivity self = this;
        Thread hot = new Thread(() -> {
            long sum = 0, n = 0;
            int probe = 0;
            long next = System.nanoTime();
            while (running) {
                for (int i = 0; i < 200000; i++) {
                    int x = (int) (n & 15);
                    sum += probeValue(x, 3);
                    probe = probeValue(x, 3);
                    n++;
                }
                if (System.nanoTime() - next >= 400_000_000L) {
                    Log.i(TAG, "HOT n=" + n + " sum=" + sum + " probe=" + probe);
                    next = System.nanoTime();
                }
            }
        }, "hot");
        Thread ref = new Thread(() -> {
            long sum = 0, n = 0;
            int probe = 0;
            long next = System.nanoTime();
            try {
                while (running) {
                    for (int i = 0; i < 20000; i++) {
                        int x = (int) (n & 15);
                        probe = (Integer) addm.invoke(null, x, 3);
                        sum += probe;
                        n++;
                    }
                    if (System.nanoTime() - next >= 400_000_000L) {
                        Log.i(TAG, "REF n=" + n + " sum=" + sum + " probe=" + probe);
                        next = System.nanoTime();
                    }
                }
            } catch (Throwable t) {
                Log.e(TAG, "ref worker died", t);
            }
        }, "ref");
        Thread grt = new Thread(() -> {
            long n = 0;
            String probe = "";
            long next = System.nanoTime();
            try {
                while (running) {
                    for (int i = 0; i < 2000; i++) {
                        probe = (String) greetm.invoke(null, "w", (int) (n & 7));
                        n++;
                    }
                    if (System.nanoTime() - next >= 400_000_000L) {
                        Log.i(TAG, "GRT n=" + n + " probe=" + probe);
                        next = System.nanoTime();
                    }
                }
            } catch (Throwable t) {
                Log.e(TAG, "grt worker died", t);
            }
        }, "grt");
        Thread ins = new Thread(() -> {
            long n = 0;
            int probe = 0;
            long next = System.nanoTime();
            try {
                while (running) {
                    for (int i = 0; i < 20000; i++) {
                        int x = (int) (n & 15);
                        probe = (Integer) scalem.invoke(self, x);
                        n++;
                    }
                    if (System.nanoTime() - next >= 400_000_000L) {
                        Log.i(TAG, "INS n=" + n + " probe=" + probe);
                        next = System.nanoTime();
                    }
                }
            } catch (Throwable t) {
                Log.e(TAG, "ins worker died", t);
            }
        }, "ins");
        Thread nat = new Thread(() -> {
            long n = 0;
            int probe = 0;
            long next = System.nanoTime();
            try {
                while (running) {
                    for (int i = 0; i < 20000; i++) {
                        int x = (int) (n & 15);
                        probe = (Integer) natm.invoke(null, x, 6);
                        n++;
                    }
                    if (System.nanoTime() - next >= 400_000_000L) {
                        Log.i(TAG, "NAT n=" + n + " probe=" + probe);
                        next = System.nanoTime();
                    }
                }
            } catch (Throwable t) {
                Log.e(TAG, "nat worker died", t);
            }
        }, "nat");
        Thread nati = new Thread(() -> {
            long n = 0;
            int probe = 0;
            long next = System.nanoTime();
            try {
                while (running) {
                    for (int i = 0; i < 20000; i++) {
                        int x = (int) (n & 15);
                        probe = (Integer) natim.invoke(self, x);
                        n++;
                    }
                    if (System.nanoTime() - next >= 400_000_000L) {
                        Log.i(TAG, "NATI n=" + n + " probe=" + probe);
                        next = System.nanoTime();
                    }
                }
            } catch (Throwable t) {
                Log.e(TAG, "nati worker died", t);
            }
        }, "nati");
        hot.start();
        ref.start();
        grt.start();
        ins.start();
        nat.start();
        nati.start();
    }

    native void nativeStart(String payloadPath, ClassLoader appLoader);
}
