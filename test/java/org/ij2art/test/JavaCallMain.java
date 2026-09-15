package org.ij2art.test;

import android.os.Looper;

public final class JavaCallMain {
    private static native void start(String payload, ClassLoader loader);
    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        boolean looper = args.length < 3 || !args[2].equals("no-main");
        if (looper) Looper.prepareMainLooper();
        start(args[1], JavaCallMain.class.getClassLoader());
        System.out.println("JAVA_READY pid=" + android.os.Process.myPid());
        if (looper) Looper.loop();
        else while (true) Thread.sleep(1000);
    }
}
