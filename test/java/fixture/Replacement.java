package fixture;

import org.ij2art.HookContext;

public final class Replacement {
    public static Object replace(HookContext context) throws Throwable {
        // The SDK contract supports before/after work and modified arguments.
        context.args[0] = ((Integer) context.args[0]) + 10;
        return ((Integer) context.callOriginal()) * 2;
    }
    public static Object skip(HookContext context) { return 42; }
    public static Object passthrough(HookContext context) throws Throwable {
        return context.callOriginal();
    }
    public static Object replaceInstance(HookContext context) throws Throwable {
        if (context.thisObject == null) throw new IllegalStateException("missing receiver");
        return ((Integer) context.callOriginal()) + 100;
    }
    public static Object replaceRef(HookContext context) throws Throwable {
        return context.callOriginal() + "!";
    }
    public static Object wrongSignature(int value) { return value; }
}
