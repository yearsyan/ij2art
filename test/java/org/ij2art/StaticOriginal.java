package org.ij2art;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/** Build-specific proof for one cold static method in a disposable process.
 * There are no concurrent callers, active target frames or compiled callers.
 * This fixture intentionally does not offer general Hook installation/deletion.
 */
public final class StaticOriginal {
    private static native Method install(Method target, Method backup, Method replacement);

    public static int target(int value) {
        if (value < 0) throw new IllegalArgumentException("original exception");
        return value + 1;
    }
    // ART owns this method's storage. It is never invoked using this declaration
    // after installation; a NEW reflected Method is created from the saved JNI ID.
    public static Object backup() { return null; }

    private static int mode;
    private static HookContext stale;

    public static Object replace(HookContext context) throws Throwable {
        stale = context;
        if (mode == 1) return 42;
        if (mode == 2)
            return (Integer) context.callOriginal() + (Integer) context.callOriginal(new Object[] {5});
        context.args[0] = (Integer) context.args[0] + 10;
        return (Integer) context.callOriginal() * 2;
    }

    public static Object invokeBackup(Method method, Object receiver, Object[] args) throws Throwable {
        try { return method.invoke(receiver, args); }
        catch (InvocationTargetException error) { throw error.getCause(); }
    }

    public static void main(String[] args) throws Throwable {
        System.load(args[0]);
        Method target = StaticOriginal.class.getDeclaredMethod("target", int.class);
        if ((Integer) target.invoke(null, 3) != 4) throw new AssertionError("before");
        Method original = install(target, StaticOriginal.class.getDeclaredMethod("backup"),
            StaticOriginal.class.getDeclaredMethod("replace", HookContext.class));
        if (original == null) throw new AssertionError("unsupported ART build or failed fixture setup");
        original.setAccessible(true);
        if ((Integer) target.invoke(null, 3) != 28) throw new AssertionError("callOriginal");
        if ((Integer) original.invoke(null, 3) != 4) throw new AssertionError("independent original");
        mode = 1;
        if ((Integer) target.invoke(null, 3) != 42) throw new AssertionError("skip");
        mode = 2;
        if ((Integer) target.invoke(null, 3) != 10) throw new AssertionError("multiple original");
        try {
            target.invoke(null, -1);
            throw new AssertionError("original exception missing");
        } catch (InvocationTargetException error) {
            if (!(error.getCause() instanceof IllegalArgumentException)
                || !"original exception".equals(error.getCause().getMessage())) throw error;
        }
        try {
            stale.callOriginal();
            throw new AssertionError("stale context accepted");
        } catch (IllegalStateException expected) { }
        // The entire fixture exits. This is NOT an unhook/reclamation test.
        System.out.println("PASS: cold isolated ART target -> static JNI -> SDK replacement -> real saved ART original; modified args, skip, repeated original, original exception, stale context (CheckJNI)");
    }
}
