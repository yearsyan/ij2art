package fixture;

import android.os.Looper;
import java.io.File;

public final class JavaCallHelper {
    private static final boolean INITIALIZED_ON_MAIN = Looper.myLooper() == Looper.getMainLooper();
    private final String prefix;
    private JavaCallHelper(String prefix) { this.prefix = prefix; }
    public static JavaCallHelper create(String prefix) { return new JavaCallHelper(prefix); }
    public String append(String suffix) { return prefix + suffix; }
    public static boolean initializedOnMain() { return INITIALIZED_ON_MAIN; }
    public static boolean ownContextLoader() {
        return Thread.currentThread().getContextClassLoader() == JavaCallHelper.class.getClassLoader();
    }
    public static String waitForFile(String path) throws Exception {
        long deadline = System.nanoTime() + 60_000_000_000L;
        while (!new File(path).exists()) {
            if (System.nanoTime() > deadline) throw new IllegalStateException("fixture release timeout");
            Thread.sleep(10);
        }
        return "released";
    }
    @Override public String toString() { throw new AssertionError("executor must not stringify application objects"); }
}
