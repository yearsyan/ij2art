package fixture;

import org.ij2art.HookContext;

public final class ConstructorReplacement {
    public static Object replace(HookContext ctx) throws Throwable {
        if (ctx.constructor == null || ctx.method != null || ctx.executable != ctx.constructor ||
            ctx.thisObject == null || !ctx.constructor.getDeclaringClass().isInstance(ctx.thisObject))
            throw new AssertionError("constructor context metadata");
        String name = ctx.constructor.getDeclaringClass().getSimpleName();
        Object receiver = ctx.thisObject;
        if (name.equals("Base")) ctx.args[0] = (Integer) ctx.args[0] + 100;
        if (name.equals("Child") && ctx.args.length == 2) {
            ctx.args[0] = (Integer) ctx.args[0] + 10;
            ctx.args[1] = ctx.args[1] + "!";
        }
        if (name.equals("Blocking")) ctx.args[0] = (Integer) ctx.args[0] + 5;
        if (name.equals("Throwing")) {
            if ((Integer) ctx.args[0] == -2) throw new IllegalStateException("ctor-handler");
            if ((Integer) ctx.args[0] == 99) return 99;
        }
        if (ctx.callOriginal() != null || receiver != ctx.thisObject)
            throw new AssertionError("constructor original must return null and retain receiver");
        if (name.equals("Child")) {
            java.lang.reflect.Field field = receiver.getClass().getField("after");
            field.setInt(receiver, field.getInt(receiver) + (ctx.args.length == 0 ? 9 : 7));
        }
        return null;
    }
}
