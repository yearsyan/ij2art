package org.ij2art;

import java.lang.reflect.Method;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.util.concurrent.atomic.AtomicReference;

public final class BridgeTest {
    private static HookContext escaped;
    public static int original(int value) { return value + 1; }
    public synchronized int instanceSync(int value) { return value; }
    public static synchronized int staticSync(int value) { return value; }
    public synchronized native int nativeSync(int value);
    public static Object skip(HookContext context) { escaped = context; return 42; }
    public static Object wrong(HookContext context) { return "wrong"; }
    public static Object throwsError(HookContext context) { throw new IllegalArgumentException("replacement failure"); }
    static int initializations;
    static final class CtorTarget {
        static { initializations++; }
        private CtorTarget(int value) {}
    }
    public static Object ctorHandler(HookContext context) {
        check(context.method == null && context.constructor == context.executable);
        check(context.constructor.getDeclaringClass() == CtorTarget.class);
        escaped = context;
        return null;
    }
    private static void check(boolean value) { if (!value) throw new AssertionError(); }
    public static void main(String[] args) throws Throwable {
        Method original = BridgeTest.class.getDeclaredMethod("original", int.class);
        Method skip = BridgeTest.class.getDeclaredMethod("skip", HookContext.class);
        check(Bridge.dispatch(1, original, null, new Object[]{3}, skip).equals(42));
        try { escaped.callOriginal(); throw new AssertionError(); }
        catch (IllegalStateException expected) { /* context closed in finally */ }
        try {
            Bridge.dispatch(2, original, null, new Object[]{3}, BridgeTest.class.getDeclaredMethod("wrong", HookContext.class));
            throw new AssertionError();
        } catch (ClassCastException expected) { }
        try {
            Bridge.dispatch(3, original, null, new Object[]{3}, BridgeTest.class.getDeclaredMethod("throwsError", HookContext.class));
            throw new AssertionError();
        } catch (IllegalArgumentException expected) { check(expected.getMessage().equals("replacement failure")); }
        // Call plan: for a given hook id (the high bits of the token) it is built only once,
        // and its validation semantics do not change.
        Bridge.CallPlan plan = Bridge.planFor(0, original);
        check(plan == Bridge.planFor(0, original));
        try { plan.validate(null, new Object[]{3L}); throw new AssertionError(); }
        catch (IllegalArgumentException expected) { }
        try { plan.validate(new Object(), null); throw new AssertionError(); }
        catch (IllegalArgumentException expected) { }
        try { plan.validate(null, new Object[]{3, 4}); throw new AssertionError(); }
        catch (IllegalArgumentException expected) { }
        plan.validate(null, new Object[]{3});
        check(plan.accepts(1) && !plan.accepts(null) && !plan.accepts("x"));
        // Validation at the dispatch level goes through the same plan: argument type errors
        // are thrown before the replacement runs.
        try { Bridge.dispatch(4, original, null, new Object[]{"x"}, skip); throw new AssertionError(); }
        catch (IllegalArgumentException expected) { }
        HookContext live = new HookContext(4, original, null, new Object[]{3}, plan);
        AtomicReference<Throwable> result = new AtomicReference<>();
        Thread other = new Thread(() -> { try { live.callOriginal(); } catch (Throwable error) { result.set(error); } });
        other.start(); other.join();
        check(result.get() instanceof IllegalStateException);
        ClassLoader loader = BridgeTest.class.getClassLoader();
        for (String name : new String[]{"instanceSync", "staticSync", "nativeSync"}) {
            Executable sync = Bridge.resolveTarget(loader, BridgeTest.class.getName() + "." + name + "(I)I");
            check(java.lang.reflect.Modifier.isSynchronized(sync.getModifiers()));
        }
        String selector = CtorTarget.class.getName() + ".<init>(I)V";
        Executable target = Bridge.resolveTarget(loader, selector);
        check(target instanceof Constructor<?> && initializations == 0);
        Bridge.initializeTarget(target);
        check(initializations == 1);
        Object receiver = new CtorTarget(1);
        Bridge.CallPlan ctorPlan = Bridge.planFor(10, target);
        check(!ctorPlan.isStatic && ctorPlan.rawResult == void.class);
        check(ctorPlan.accepts(null) && !ctorPlan.accepts(receiver));
        check(Bridge.dispatch(10L << 32, target, receiver, new Object[]{1},
                BridgeTest.class.getDeclaredMethod("ctorHandler", HookContext.class)) == null);
        check(escaped.thisObject == receiver && escaped.executable == target);
        try { ctorPlan.validate(null, new Object[]{1}); throw new AssertionError(); }
        catch (IllegalArgumentException expected) { }
        try { ctorPlan.validate(receiver, new Object[]{1L}); throw new AssertionError(); }
        catch (IllegalArgumentException expected) { }
        try {
            Bridge.dispatch(10L << 32, target, receiver, new Object[]{1}, skip);
            throw new AssertionError();
        } catch (ClassCastException expected) { }
        for (String invalid : new String[]{".<init>(I)I", ".<clinit>()V", ".<other>()V"}) {
            try { Bridge.resolveTarget(loader, CtorTarget.class.getName() + invalid); throw new AssertionError(); }
            catch (IllegalArgumentException expected) { }
        }
        try { Bridge.resolveReplacement(loader, loader, selector, selector); throw new AssertionError(); }
        catch (IllegalArgumentException expected) { }
        try { Bridge.resolveTarget(loader, "java.lang.String.<init>()V"); throw new AssertionError(); }
        catch (IllegalArgumentException expected) { }
        check(Bridge.resolveTarget(loader, BridgeTest.class.getName() + ".original(I)I") instanceof Method);
        System.out.println("PASS: constructor lookup without initialization, metadata, void result and argument checks");
        System.out.println("PASS: Java replacement dispatch, cached call plans, return types, original argument checks, exceptions and context lifetime (no ART hook simulated)");
    }
}
