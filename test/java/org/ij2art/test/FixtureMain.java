package org.ij2art.test;

// Shared bootstrap for the four Hook fixture processes (constructors, synchronized,
// native binding, hook update). args[2] selects the fixture side (ctor/sync/binding/
// update); its uppercase form is also the READY tag the runner greps for
// (CTOR_READY, SYNC_READY, BINDING_READY, UPDATE_READY).
public final class FixtureMain {
    private static native void start(String payload, ClassLoader loader, String fixture);
    private static native int processId();
    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        start(args[1], FixtureMain.class.getClassLoader(), args[2]);
        System.out.println(args[2].toUpperCase() + "_READY pid=" + processId());
        while (true) Thread.sleep(1000);
    }
}
