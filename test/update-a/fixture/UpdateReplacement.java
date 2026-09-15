package fixture;
import org.ij2art.HookContext;
public final class UpdateReplacement {
    public static Object replace(HookContext ctx) throws Throwable {
        if (ctx.method.getName().equals("syncValue") && !Thread.holdsLock(ctx.thisObject))
            throw new AssertionError("callback lost monitor");
        int x = (Integer) ctx.args[0];
        if (x == 99) return 1099;
        int result = (Integer) ctx.callOriginal();
        if (x == 97) {
            // This happens AFTER the update/DEL. A leased old invocation must
            // keep its context valid and recursion must still identify its slot.
            result += (Integer) ctx.method.invoke(ctx.thisObject, 6);
            result += (Integer) ctx.callOriginal(new Object[]{7});
        }
        return result + 100;
    }
}
