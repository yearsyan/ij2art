package fixture;
import org.ij2art.HookContext;

public final class NativeBindingReplacement {
    public static Object replace(HookContext ctx) throws Throwable {
        if (ctx.method.getName().startsWith("sync")) {
            Object lock = ctx.thisObject != null ? ctx.thisObject : ctx.method.getDeclaringClass();
            if (!Thread.holdsLock(lock)) throw new AssertionError("replacement lost monitor");
        }
        if (((Integer) ctx.args[0]) == 1) return 1001;
        return ((Integer) ctx.callOriginal()) + 1000;
    }
}
