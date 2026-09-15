package org.ij2art;

import java.lang.reflect.Method;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;

/** A context belongs to one synchronous replacement invocation on its App thread.
 *  For a synchronized target, ART holds the receiver/declaring-class monitor
 *  around the entire replacement, including calls to the saved original.
 *  A callback update does not invalidate this invocation's original-call token. */
public final class HookContext {
    /** The original Method or Constructor. */
    public final Executable executable;
    /** Ordinary method target; null for a constructor. */
    public final Method method;
    /** Constructor target; null for an ordinary method. */
    public final Constructor<?> constructor;
    /** For constructors, the already-allocated object being initialized. */
    public final Object thisObject;
    public final Object[] args;
    private final long token;
    private final Thread owner;
    private final Bridge.CallPlan plan;
    private volatile boolean active = true;

    HookContext(long token, Executable target, Object receiver, Object[] args, Bridge.CallPlan plan) {
        this.token = token;
        this.executable = target;
        this.method = target instanceof Method ? (Method) target : null;
        this.constructor = target instanceof Constructor<?> ? (Constructor<?>) target : null;
        this.thisObject = receiver;
        this.args = args;
        this.plan = plan;
        this.owner = Thread.currentThread();
    }

    /** Calls the original implementation (the latest JNI binding for native targets).
     *  For a constructor, initializes thisObject
     *  in place and returns null; it never allocates a second object. */
    public Object callOriginal() throws Throwable {
        return callOriginal(args);
    }

    /** Calls the saved original implementation with replacement arguments. */
    public Object callOriginal(Object[] arguments) throws Throwable {
        if (!active || owner != Thread.currentThread())
            throw new IllegalStateException("HookContext is expired or belongs to another thread");
        if (arguments == null) throw new NullPointerException("arguments");
        // The snapshot is what isolates us from external mutation: validation and the native
        // unboxing see the same array.
        Object[] snapshot = arguments.clone();
        plan.validate(thisObject, snapshot);
        return callOriginalNative(token, thisObject, snapshot);
    }

    // Native entry additionally validates the token, thread, lifetime and argument types.
    // A Java-side check alone is insufficient: code may use reflection on this object.
    private static native Object callOriginalNative(long token, Object receiver, Object[] arguments)
            throws Throwable;

    void close() { active = false; }
}
