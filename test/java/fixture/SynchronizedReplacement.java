package fixture;

import java.lang.reflect.InvocationTargetException;
import org.ij2art.HookContext;

public final class SynchronizedReplacement {
    public static Object replace(HookContext ctx) throws Throwable {
        Object lock = ctx.thisObject == null ? ctx.method.getDeclaringClass() : ctx.thisObject;
        if (!Thread.holdsLock(lock)) throw new AssertionError("callback entered without target monitor");
        int mode = (Integer) ctx.args[0];
        if (mode == 1) return 101;
        if (mode == 4) throw new IllegalStateException("sync-handler");
        if (mode == 9) return "bad return";
        if (mode == 6) {
            try { ctx.method.getDeclaringClass().getMethod("awaitSignal", Object.class).invoke(null, lock); }
            catch (InvocationTargetException error) { throw error.getCause(); }
        }
        int result = (Integer) ctx.callOriginal();
        if (mode == 2) result += (Integer) ctx.callOriginal();
        if (!Thread.holdsLock(lock)) throw new AssertionError("original lost target monitor");
        return result + 100;
    }
}
