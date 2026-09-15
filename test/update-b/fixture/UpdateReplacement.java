package fixture;
import org.ij2art.HookContext;
public final class UpdateReplacement {
    public static Object replace(HookContext ctx) throws Throwable { return run(ctx, 200); }
    public static Object alternate(HookContext ctx) throws Throwable { return run(ctx, 300); }
    private static Object run(HookContext ctx, int bonus) throws Throwable {
        if (ctx.method.getName().equals("syncValue") && !Thread.holdsLock(ctx.thisObject))
            throw new AssertionError("callback lost monitor");
        if (((Integer) ctx.args[0]) == 99) return 999 + bonus;
        return ((Integer) ctx.callOriginal()) + bonus;
    }
    public static Object throwing(HookContext ctx) { throw new IllegalArgumentException("replacement-error"); }
    public static Object wrong(HookContext ctx) { return "bad-result"; }
    public static int invalid(int value) { return value; }
}
