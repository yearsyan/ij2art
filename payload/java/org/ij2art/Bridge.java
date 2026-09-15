package org.ij2art;

import java.lang.reflect.Method;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Modifier;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/** Method lookup deliberately uses the supplied loader and exact descriptors. */
public final class Bridge {
    private Bridge() {}

    private static Class<?> type(String s, int[] cursor, ClassLoader loader, boolean allowVoid)
            throws ClassNotFoundException {
        int start = cursor[0];
        if (start >= s.length()) throw new IllegalArgumentException("missing descriptor type");
        char c = s.charAt(cursor[0]++);
        switch (c) {
            case 'V': if (allowVoid) return void.class; break;
            case 'Z': return boolean.class;
            case 'B': return byte.class;
            case 'C': return char.class;
            case 'S': return short.class;
            case 'I': return int.class;
            case 'J': return long.class;
            case 'F': return float.class;
            case 'D': return double.class;
            case 'L': {
                int end = s.indexOf(';', cursor[0]);
                if (end <= cursor[0]) break;
                String name = s.substring(cursor[0], end);
                if (name.indexOf('.') >= 0 || name.indexOf('[') >= 0)
                    throw new IllegalArgumentException("invalid object descriptor");
                cursor[0] = end + 1;
                return Class.forName(name.replace('/', '.'), false, loader);
            }
            case '[': {
                while (cursor[0] < s.length() && s.charAt(cursor[0]) == '[') cursor[0]++;
                if (cursor[0] - start > 255) break;
                type(s, cursor, loader, false);
                return Class.forName(s.substring(start, cursor[0]).replace('/', '.'), false, loader);
            }
            default: break;
        }
        throw new IllegalArgumentException("invalid descriptor at " + start);
    }

    public static Executable resolve(ClassLoader loader, String selector) throws Exception {
        int open = selector.indexOf('(');
        int dot = selector.lastIndexOf('.', open);
        if (open < 0 || dot <= 0 || dot + 1 == open)
            throw new IllegalArgumentException("expected class.method(args)return");
        Class<?> owner = Class.forName(selector.substring(0, dot), false, loader);
        String name = selector.substring(dot + 1, open);
        if (name.startsWith("<") && !name.equals("<init>"))
            throw new IllegalArgumentException("class initializers and other special methods are unsupported");
        int[] cursor = {open + 1};
        List<Class<?>> params = new ArrayList<>();
        while (cursor[0] < selector.length() && selector.charAt(cursor[0]) != ')') {
            params.add(type(selector, cursor, loader, false));
            if (params.size() > 255) throw new IllegalArgumentException("too many parameters");
        }
        if (cursor[0] >= selector.length()) throw new IllegalArgumentException("missing )");
        cursor[0]++;
        Class<?> result = type(selector, cursor, loader, true);
        if (cursor[0] != selector.length()) throw new IllegalArgumentException("trailing descriptor");
        if (name.equals("<init>")) {
            if (result != void.class) throw new IllegalArgumentException("constructor return type must be V");
            return owner.getDeclaredConstructor(params.toArray(new Class<?>[0]));
        }
        Method method = owner.getDeclaredMethod(name, params.toArray(new Class<?>[0]));
        if (method.getReturnType() != result) throw new IllegalArgumentException("return type mismatch");
        int modifiers = method.getModifiers();
        if (Modifier.isAbstract(modifiers) || method.isBridge())
            throw new IllegalArgumentException("abstract and bridge methods are unsupported");
        // Native targets are admitted by the ART backend (bound JNI functions);
        // the lazy dlsym stub and critical natives are not.
        return method;
    }

    /** Admission for a replacement target. The saved original is invoked with
     *  CallNonvirtual/CallStatic, so virtual instance methods are safe; bound
     *  native originals keep their native backup. For synchronized targets,
     *  GenericJni owns the monitor around the entire replacement invocation. */
    public static Executable resolveTarget(ClassLoader appLoader, String selector) throws Exception {
        Executable method = resolve(appLoader, selector);
        String owner = method.getDeclaringClass().getName();
        if (method instanceof Constructor<?> && method.getDeclaringClass() == String.class)
            throw new IllegalArgumentException("String constructors use ART StringFactory and are unsupported");
        if (owner.equals("org.ij2art.Bridge") || owner.equals("org.ij2art.HookContext")
                || owner.equals("org.ij2art.Backup"))
            throw new IllegalArgumentException("hooking the Hook SDK itself is unsupported");
        return method;
    }

    public static Executable[] resolveReplacement(ClassLoader appLoader, ClassLoader dexLoader,
                                               String targetName, String replacementName)
            throws Exception {
        Executable target = resolveTarget(appLoader, targetName);
        return new Executable[] {target, resolveHandler(dexLoader, replacementName)};
    }

    /** Resolve a new callback independently of the already-converted target. */
    public static Method resolveHandler(ClassLoader dexLoader, String replacementName) throws Exception {
        Executable resolved = resolve(dexLoader, replacementName);
        if (!(resolved instanceof Method))
            throw new IllegalArgumentException("replacement must be a method, not a constructor");
        Method replacement = (Method) resolved;
        if (Modifier.isNative(replacement.getModifiers()))
            throw new IllegalArgumentException("replacement must be a managed (non-native) method");
        if (replacement.getDeclaringClass().getClassLoader() != dexLoader)
            throw new IllegalArgumentException("replacement resolved outside supplied dex_id");
        if (!Modifier.isStatic(replacement.getModifiers()) || !Modifier.isPublic(replacement.getModifiers()))
            throw new IllegalArgumentException("replacement must be public static");
        Class<?>[] to = replacement.getParameterTypes();
        if (replacement.getReturnType() != Object.class || to.length != 1 || to[0] != HookContext.class)
            throw new IllegalArgumentException("replacement must be static Object method(org.ij2art.HookContext)");
        return replacement;
    }

    /** Complete target initialization before changing ArtMethod metadata. */
    public static void initializeTarget(Executable target) throws ClassNotFoundException {
        Class<?> owner = target.getDeclaringClass();
        Class.forName(owner.getName(), true, owner.getClassLoader());
    }

    private static Class<?> boxed(Class<?> type) {
        if (type == boolean.class) return Boolean.class;
        if (type == byte.class) return Byte.class;
        if (type == char.class) return Character.class;
        if (type == short.class) return Short.class;
        if (type == int.class) return Integer.class;
        if (type == long.class) return Long.class;
        if (type == float.class) return Float.class;
        if (type == double.class) return Double.class;
        return type;
    }

    /** Immutable per-hook call metadata derived once from the target executable,
     *  then shared by dispatch validation, the result check and
     *  HookContext.callOriginal -- no reflection or array cloning per hit. */
    static final class CallPlan {
        final boolean isStatic;
        final Class<?> declaring;
        final Class<?>[] rawParams;    // null check is based on isPrimitive
        final Class<?>[] boxedParams;  // type check is based on isInstance
        final Class<?> rawResult;
        final Class<?> boxedResult;    // void remains void.class
        final String resultName;

        CallPlan(Executable method) {
            isStatic = Modifier.isStatic(method.getModifiers());
            declaring = method.getDeclaringClass();
            rawParams = method.getParameterTypes();
            boxedParams = new Class<?>[rawParams.length];
            for (int i = 0; i < rawParams.length; i++) boxedParams[i] = boxed(rawParams[i]);
            rawResult = method instanceof Constructor<?> ? void.class : ((Method) method).getReturnType();
            boxedResult = rawResult == void.class ? void.class : boxed(rawResult);
            resultName = rawResult.getName();
        }

        void validate(Object receiver, Object[] args) {
            if (isStatic) {
                if (receiver != null)
                    throw new IllegalArgumentException("static method receiver must be null");
            } else if (receiver == null || !declaring.isInstance(receiver)) {
                throw new IllegalArgumentException("invalid method receiver");
            }
            if (args == null || args.length != rawParams.length)
                throw new IllegalArgumentException("argument count mismatch");
            for (int i = 0; i < rawParams.length; i++) {
                if (args[i] == null ? rawParams[i].isPrimitive() : !boxedParams[i].isInstance(args[i]))
                    throw new IllegalArgumentException("argument type mismatch at " + i);
            }
        }

        boolean accepts(Object result) {
            if (rawResult == void.class) return result == null;
            if (result == null) return !rawResult.isPrimitive();
            return boxedResult.isInstance(result);
        }
    }

    private static final ConcurrentHashMap<Long, CallPlan> PLANS = new ConcurrentHashMap<>();

    /** One plan per hook id (token high bits); ids are never reused, even after removal. */
    static CallPlan planFor(long hookId, Executable method) {
        CallPlan plan = PLANS.get(hookId);
        if (plan != null) return plan;
        CallPlan built = new CallPlan(method);
        plan = PLANS.putIfAbsent(hookId, built);
        return plan != null ? plan : built;
    }

    /** ART adapter enters this only after pinning a valid original-call token. */
    public static Object dispatch(long token, Executable target, Object receiver, Object[] args,
                                  Method replacement) throws Throwable {
        CallPlan plan = planFor(token >>> 32, target);
        plan.validate(receiver, args);
        // The args array is freshly built per call by the native capture path and is solely
        // owned, so the clone can be skipped; HookContext becomes its only owner.
        HookContext context = new HookContext(token, target, receiver, args, plan);
        try {
            Object result;
            try { result = replacement.invoke(null, context); }
            catch (InvocationTargetException error) { throw error.getCause(); }
            if (!plan.accepts(result))
                throw new ClassCastException("replacement result does not match " + plan.resultName);
            return result;
        } finally {
            context.close();
        }
    }
}
