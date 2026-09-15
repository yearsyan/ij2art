package fixture;

import org.ij2art.HookContext;

/** Replacement methods for the real-App verification APK (test/apk). */
public final class ReplacementApk {
    private ReplacementApk() {}

    /** add(II)I -> callOriginal(a+1000, b): probe becomes x+1003 instead of x+3. */
    public static Object replace(HookContext ctx) throws Throwable {
        ctx.args[0] = (Integer) ctx.args[0] + 1000;
        return ctx.callOriginal();
    }

    /** greet(Ljava/lang/String;I)Ljava/lang/String; -> skip original entirely. */
    public static Object skip(HookContext ctx) throws Throwable {
        return "HOOKED[" + ctx.args[0] + "]";
    }

    /** instanceScale(I)I -> callOriginal(v+100): probe becomes (x+100)*3. */
    public static Object shift(HookContext ctx) throws Throwable {
        ctx.args[0] = (Integer) ctx.args[0] + 100;
        return ctx.callOriginal();
    }

    public static Object blocked(HookContext ctx) throws Throwable {
        return (Integer) ctx.callOriginal() + 1000;
    }

    /** natMul(II)I (bound JNI) -> callOriginal(a+700, b): probe becomes (x+700)*6+1. */
    public static Object natShift(HookContext ctx) throws Throwable {
        ctx.args[0] = (Integer) ctx.args[0] + 700;
        return ctx.callOriginal();
    }

    /** natInstanceScale(I)I (instance, bound JNI) -> callOriginal(v+80): (x+80)*5+2. */
    public static Object natShift2(HookContext ctx) throws Throwable {
        ctx.args[0] = (Integer) ctx.args[0] + 80;
        return ctx.callOriginal();
    }
}
