package org.ij2art.tracer;

import android.util.Log;

import org.ij2art.HookContext;

/** Generic observation replacement embedded into the ij2art CLI as a builtin DEX.
 *  Nothing is loaded into an app until `dex upload --builtin tracer` or
 *  `hook trace --target ...` runs. On every intercepted call it writes to logcat
 *  (tag "ij2art.trace"): the target, thread, boxed arguments and caller stack on
 *  entry, then the result or thrown exception with wall time on exit. The original
 *  implementation always runs; the tracer only observes. */
public final class Tracer {
    private static final String TAG = "ij2art.trace";
    /** Per-value render cap so a huge toString/array cannot blow the logcat buffer. */
    private static final int VALUE_LIMIT = 256;
    /** Retained caller frames per entry; deeper stacks end with a "... N more" line. */
    private static final int STACK_LIMIT = 24;

    private Tracer() {}

    /** Replacement contract: public static Object method(org.ij2art.HookContext).
     *  For a constructor target, callOriginal initializes ctx.thisObject in place and
     *  returns null, which is also what this method returns. */
    public static Object trace(HookContext ctx) throws Throwable {
        String target = String.valueOf(ctx.executable);
        try {
            StringBuilder enter = new StringBuilder();
            Thread thread = Thread.currentThread();
            enter.append("enter ").append(target)
                    .append(" thread=").append(thread.getName())
                    .append('#').append(thread.getId());
            Object[] args = ctx.args;
            if (args != null) {
                for (int i = 0; i < args.length; i++) {
                    enter.append("\n  arg[").append(i).append("]=").append(render(args[i]));
                }
            }
            int kept = 0;
            StackTraceElement[] frames = new Throwable().getStackTrace();
            for (StackTraceElement frame : frames) {
                String owner = frame.getClassName();
                // Drop only the dispatch machinery itself; the hooked frame and every real
                // caller (including test fixtures under org.ij2art.test) stay visible.
                if (owner.equals("org.ij2art.Bridge") || owner.startsWith("org.ij2art.Bridge$")
                        || owner.equals("org.ij2art.HookContext")
                        || owner.startsWith("org.ij2art.tracer.")
                        || owner.startsWith("java.lang.reflect."))
                    continue;
                if (kept == STACK_LIMIT) {
                    enter.append("\n  ... ").append(frames.length - kept).append(" more");
                    break;
                }
                kept++;
                enter.append("\n  at ").append(frame);
            }
            Log.i(TAG, enter.toString());
        } catch (Throwable logging) {
            // Observation must never break the intercepted call.
        }
        long start = System.nanoTime();
        try {
            Object result = ctx.callOriginal();
            long ms = (System.nanoTime() - start) / 1000000L;
            try {
                Log.i(TAG, "exit " + target + " after " + ms + " ms: "
                        + (result == null ? "(null/void)" : render(result)));
            } catch (Throwable logging) {
            }
            return result;
        } catch (Throwable call) {
            long ms = (System.nanoTime() - start) / 1000000L;
            try {
                Log.i(TAG, "throw " + target + " after " + ms + " ms: "
                        + call.getClass().getName() + ": " + call.getMessage());
            } catch (Throwable logging) {
            }
            throw call;
        }
    }

    private static String render(Object value) {
        if (value == null) return "null";
        String text;
        try {
            if (value instanceof Object[]) text = java.util.Arrays.deepToString((Object[]) value);
            else if (value instanceof int[]) text = java.util.Arrays.toString((int[]) value);
            else if (value instanceof long[]) text = java.util.Arrays.toString((long[]) value);
            else if (value instanceof byte[]) text = java.util.Arrays.toString((byte[]) value);
            else if (value instanceof short[]) text = java.util.Arrays.toString((short[]) value);
            else if (value instanceof char[]) text = java.util.Arrays.toString((char[]) value);
            else if (value instanceof boolean[]) text = java.util.Arrays.toString((boolean[]) value);
            else if (value instanceof float[]) text = java.util.Arrays.toString((float[]) value);
            else if (value instanceof double[]) text = java.util.Arrays.toString((double[]) value);
            else text = String.valueOf(value);
        } catch (Throwable failure) {
            text = "<toString threw " + failure.getClass().getSimpleName() + ">";
        }
        if (text.length() > VALUE_LIMIT)
            text = text.substring(0, VALUE_LIMIT) + "...(" + text.length() + " chars)";
        return text;
    }
}
