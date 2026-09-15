package fixture;
import org.ij2art.HookContext;
public final class FailingReplacement {
    static { if (System.nanoTime() != 0) throw new IllegalStateException("initializer-error"); }
    public static Object replace(HookContext ctx) { return 999; }
}
