package org.ij2art.test;

public final class Main {
    private static native void start(String payload, ClassLoader loader);
    public static int target(int value) { return value + 1; }
    public static int target(String value) { return value.length(); }
    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        if (args.length > 2) System.load(args[2]); // Optional native inline fixture.
        start(args[1], Main.class.getClassLoader());
        System.out.println("ART_API_TEST_READY pid=" + android.os.Process.myPid());
        while (true) {
            if (target(3) != 4) throw new AssertionError("target changed without a supported Hook");
            if (args.length > 2) System.gc(); // Exercise ART while native hooks are active.
            Thread.sleep(100);
        }
    }
}
