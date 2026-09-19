package org.ij2art;

import android.os.Handler;
import android.os.Looper;
import android.util.JsonReader;
import android.util.JsonToken;
import java.io.StringReader;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;

/** Typed method calls, not Java source evaluation. No native callbacks on execution threads. */
public final class JavaCalls {
    private JavaCalls() {}
    private static final int SLOTS = 16;
    private static final int DEFAULT_MAX_STRING = 512;
    private static final int DEFAULT_MAX_BYTES = 8192;
    // One response frame is IJ2ART_RSP_DATA_MAX=16344 bytes; leave margin for the JSON envelope.
    private static final int HARD_MAX = 15872;
    private static final Map<Long, Job> JOBS = new LinkedHashMap<>();
    private static long nextId = 1;
    private static boolean closing;

    // All registry operations are short; no target method/class initializer runs under this lock.
    public static synchronized long submit(ClassLoader loader, long dexId, byte[] input,
                                            boolean main) throws Exception {
        if (closing) throw new IllegalStateException("Java executor is closing");
        if (JOBS.size() >= SLOTS) throw new IllegalStateException("16 Java job slots occupied; java del a completed job");
        if (input.length == 0 || input.length > 3992) throw invalid("JSON must contain 1..3992 UTF-8 bytes");
        String text = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(input)).toString();
        Request request = parse(text);
        Looper looper = main ? Looper.getMainLooper() : null;
        if (main && looper == null) throw new IllegalStateException("App main Looper is not ready");
        Job job = new Job(nextId++, dexId, loader, request, main);
        JOBS.put(job.id, job);
        try {
            if (main) {
                if (!new Handler(looper).post(job)) throw new IllegalStateException("main Looper rejected Java call");
            } else {
                // Unnamed: the runtime assigns the same sequential "Thread-N" name as any
                // other unnamed thread in the process, so jobs stay out of name-based scans.
                Thread thread = new Thread(job);
                thread.setDaemon(true);
                thread.start();
            }
        } catch (Throwable error) {
            JOBS.remove(job.id);
            throw error;
        }
        return job.id;
    }

    public static synchronized byte[] query(long id) throws Exception {
        return wire(find(id).snapshot(true));
    }

    public static synchronized byte[] list() throws Exception {
        JSONArray records = new JSONArray();
        for (Job job : JOBS.values()) records.put(job.snapshot(false));
        return wire(new JSONObject().put("records", records));
    }

    public static synchronized byte[] drop(long id) throws Exception {
        Job job = find(id);
        if (!job.finished()) throw new IllegalStateException("Java job is queued/running; it cannot be cancelled by java del");
        JOBS.remove(id);
        return wire(new JSONObject().put("id", id).put("deleted", true));
    }

    public static synchronized boolean references(long dexId) {
        for (Job job : JOBS.values()) if (job.dexId == dexId && !job.finished()) return true;
        return false;
    }

    public static synchronized boolean close() {
        closing = true;
        for (Job job : JOBS.values()) if (!job.finished()) return false;
        JOBS.clear();
        return true;
    }

    private static Job find(long id) {
        Job job = JOBS.get(id);
        if (job == null) throw invalid("unknown Java job_id in this process: " + id);
        return job;
    }

    private static final class Job implements Runnable {
        final long id, dexId;
        final boolean main;
        ClassLoader loader;
        Request request;
        volatile int state; // QUEUED=0, RUNNING=1, SUCCEEDED=2, FAILED=3 (release publishes results)
        JSONArray results;
        JSONObject failure;
        boolean truncated;

        Job(long id, long dexId, ClassLoader loader, Request request, boolean main) {
            this.id = id; this.dexId = dexId; this.loader = loader; this.request = request; this.main = main;
        }
        boolean finished() { return state >= 2; }
        JSONObject snapshot(boolean details) throws Exception {
            int observed = state;
            JSONObject out = new JSONObject().put("id", id)
                .put("dex_id", dexId == 0 ? JSONObject.NULL : Long.toUnsignedString(dexId))
                .put("thread", main ? "main" : "new")
                .put("state", new String[]{"QUEUED", "RUNNING", "SUCCEEDED", "FAILED"}[observed]);
            // Execution owns these fields until the terminal volatile publication.
            if (details && observed >= 2) {
                out.put("results", results).put("results_truncated", truncated);
                if (failure != null) out.put("error", failure);
            }
            return out;
        }
        @Override public void run() {
            state = 1;
            Thread thread = Thread.currentThread();
            ClassLoader previous = null;
            boolean havePrevious = false;
            Map<String, Object> refs = new HashMap<>();
            results = new JSONArray();
            int index = 0, outputBytes = 0;
            try {
                previous = thread.getContextClassLoader();
                havePrevious = true;
                thread.setContextClassLoader(loader);
                for (; index < request.calls.length; ++index) {
                    Call call = request.calls[index];
                    Class<?> owner = type(call.owner, loader);
                    Class<?>[] types = new Class<?>[call.args.length];
                    Object[] values = new Object[types.length];
                    for (int a = 0; a < types.length; ++a) {
                        types[a] = type(call.args[a].type, loader);
                        values[a] = convert(types[a], call.args[a].value, refs);
                    }
                    Method method = method(owner, call.method, types);
                    boolean isStatic = Modifier.isStatic(method.getModifiers());
                    if (isStatic != (call.receiver == null))
                        throw invalid("static calls omit receiver; instance calls require receiver:{ref:...}");
                    Object receiver = call.receiver == null ? null : refs.get(call.receiver);
                    if (!isStatic && (receiver == null || !owner.isInstance(receiver)))
                        throw invalid("receiver is null or not an instance of " + owner.getName());
                    method.setAccessible(true); // Android hidden-API/access restrictions still apply.
                    Object value = method.invoke(receiver, values);
                    if (call.save != null) refs.put(call.save, value);
                    JSONObject result = result(index, method.getReturnType(), value, request.maxString);
                    int size = wire(result).length;
                    if (outputBytes + size <= request.maxBytes) { results.put(result); outputBytes += size; }
                    else { truncated = true; results.put(new JSONObject().put("index", index).put("omitted", true)); }
                }
            } catch (Throwable error) {
                failure = error(index, error);
            } finally {
                try { if (havePrevious) thread.setContextClassLoader(previous); }
                catch (Throwable error) { if (failure == null) failure = error(index, error); }
                // Do not keep app objects, their loaders, or large arguments in completed job records.
                refs.clear(); request.calls = null; loader = null;
                state = failure == null ? 2 : 3;
            }
        }
    }

    private static JSONObject result(int index, Class<?> declared, Object value, int maxString) throws Exception {
        JSONObject out = new JSONObject().put("index", index).put("type", clip(declared.getTypeName(), 256));
        if (value == null) return out.put("value", JSONObject.NULL);
        if (value instanceof String) {
            String text = (String)value;
            out.put("value", clip(text, maxString));
            if (text.length() > maxString) out.put("truncated", true);
        } else if (value instanceof Long) {
            out.put("value", value.toString()); // Preserve all 64 bits for JSON clients.
        } else if (value instanceof Boolean || value instanceof Byte || value instanceof Short || value instanceof Integer) {
            out.put("value", value);
        } else if (value instanceof Float || value instanceof Double) {
            double number = ((Number)value).doubleValue();
            out.put("value", Double.isNaN(number) || Double.isInfinite(number) ? value.toString() : value);
        } else if (value instanceof Character) {
            out.put("value", value.toString());
        } else {
            // No implicit toString(), field traversal, or retention of arbitrary application objects.
            out.put("class", clip(value.getClass().getName(), 256)).put("opaque", true);
        }
        return out;
    }

    private static JSONObject error(int index, Throwable error) {
        if (error instanceof InvocationTargetException && error.getCause() != null) error = error.getCause();
        JSONObject out = new JSONObject();
        try {
            out.put("index", index).put("type", clip(error.getClass().getName(), 256));
            out.put("message", clip(error.getMessage(), 512));
        } catch (Throwable ignored) { /* A hostile Throwable.getMessage must not escape onto the main Looper. */ }
        return out;
    }
    private static String clip(String text, int limit) {
        if (text == null) return "";
        int end = Math.min(text.length(), limit);
        if (end < text.length() && end > 0 && Character.isHighSurrogate(text.charAt(end - 1))) --end;
        return text.substring(0, end);
    }
    private static byte[] wire(JSONObject json) {
        return json.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static final class Arg {
        final String type;
        final Object value;
        Arg(String type, Object value) { this.type = type; this.value = value; }
    }
    private static final class Call {
        final String owner, method, receiver, save;
        final Arg[] args;
        Call(String owner, String method, String receiver, String save, Arg[] args) {
            this.owner = owner; this.method = method; this.receiver = receiver; this.save = save; this.args = args;
        }
    }
    private static final class Request {
        Call[] calls;
        final int maxString, maxBytes;
        Request(Call[] calls, int maxString, int maxBytes) {
            this.calls = calls; this.maxString = maxString; this.maxBytes = maxBytes;
        }
    }
    private static final class NumberToken {
        final String text;
        NumberToken(String text) { this.text = text; }
    }

    // Android's strict streaming JSON parser handles grammar/escaping; this only builds bounded values.
    private static Object read(JsonReader reader, int depth) throws Exception {
        if (depth > 16) throw invalid("JSON nesting exceeds 16");
        switch (reader.peek()) {
            case BEGIN_OBJECT: {
                JSONObject object = new JSONObject();
                reader.beginObject();
                while (reader.hasNext()) {
                    String key = reader.nextName();
                    if (object.has(key)) throw invalid("duplicate JSON field: " + key);
                    object.put(key, read(reader, depth + 1));
                }
                reader.endObject();
                return object;
            }
            case BEGIN_ARRAY: {
                JSONArray array = new JSONArray();
                reader.beginArray();
                while (reader.hasNext()) array.put(read(reader, depth + 1));
                reader.endArray();
                return array;
            }
            case STRING: return reader.nextString();
            case NUMBER: return new NumberToken(reader.nextString());
            case BOOLEAN: return reader.nextBoolean();
            case NULL: reader.nextNull(); return JSONObject.NULL;
            default: throw invalid("expected a JSON value");
        }
    }

    private static Request parse(String text) throws Exception {
        checkCharacters(text);
        Object root;
        try (JsonReader reader = new JsonReader(new StringReader(text))) {
            reader.setLenient(false);
            root = read(reader, 0);
            if (reader.peek() != JsonToken.END_DOCUMENT) throw invalid("trailing JSON content");
        }
        JSONObject object = object(root, "request");
        fields(object, "calls", "maxString", "maxBytes");
        int maxString = limit(object, "maxString", DEFAULT_MAX_STRING, 64, HARD_MAX);
        int maxBytes = limit(object, "maxBytes", DEFAULT_MAX_BYTES, 512, HARD_MAX);
        JSONArray calls = object.getJSONArray("calls");
        if (calls.length() == 0 || calls.length() > 32) throw invalid("calls must contain 1..32 method calls");
        Call[] out = new Call[calls.length()];
        Set<String> saved = new HashSet<>();
        for (int i = 0; i < calls.length(); ++i) {
            JSONObject call = object(calls.get(i), "call");
            fields(call, "class", "method", "args", "receiver", "save");
            String owner = string(call, "class"), method = string(call, "method");
            if (method.startsWith("<")) throw invalid("only methods are supported; no constructors or initializers");
            String receiver = call.has("receiver") ? reference(call.get("receiver"), saved) : null;
            JSONArray args = call.has("args") ? call.getJSONArray("args") : new JSONArray();
            if (args.length() > 255) throw invalid("too many method parameters");
            Arg[] parameters = new Arg[args.length()];
            for (int a = 0; a < args.length(); ++a) {
                JSONObject arg = object(args.get(a), "argument");
                fields(arg, "type", "value");
                Object value = arg.get("value");
                validateValue(value, saved);
                parameters[a] = new Arg(string(arg, "type"), value);
            }
            String save = call.has("save") ? string(call, "save") : null;
            if (save != null && !saved.add(save)) throw invalid("duplicate save name: " + save);
            out[i] = new Call(owner, method, receiver, save, parameters);
        }
        return new Request(out, maxString, maxBytes);
    }

    private static int limit(JSONObject object, String name, int fallback, int min, int max) throws Exception {
        if (!object.has(name)) return fallback;
        Object value = object.get(name);
        if (!(value instanceof Integer)) throw invalid(name + " must be an integer in " + min + ".." + max);
        int n = (Integer)value;
        if (n < min || n > max) throw invalid(name + " must be an integer in " + min + ".." + max);
        return n;
    }

    // AOSP JsonReader still accepts unknown escapes, raw controls and mixed-case
    // literals in strict mode. Close those lexical gaps; JsonReader owns grammar.
    private static void checkCharacters(String text) {
        boolean quoted = false;
        for (int i = 0; i < text.length(); ++i) {
            char c = text.charAt(i);
            if (c == '"') { quoted = !quoted; continue; }
            if (quoted) {
                if (c < 0x20) throw invalid("unescaped control character in JSON string");
                if (c == '\\') {
                    if (++i == text.length()) throw invalid("unterminated JSON escape");
                    char escape = text.charAt(i);
                    if (escape == 'u') {
                        for (int n = 0; n < 4; ++n) {
                            if (++i == text.length() || "0123456789abcdefABCDEF".indexOf(text.charAt(i)) < 0)
                                throw invalid("invalid JSON Unicode escape");
                        }
                    } else if ("\"\\/bfnrt".indexOf(escape) < 0) throw invalid("invalid JSON escape");
                }
            } else {
                if ((c < 0x20 && c != '\t' && c != '\r' && c != '\n') || c == '\ufeff')
                    throw invalid("invalid JSON whitespace");
                if ((c == 'e' || c == 'E') && i > 0 && text.charAt(i - 1) >= '0' && text.charAt(i - 1) <= '9')
                    continue; // Numeric exponent; validated by JsonReader.
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
                    int start = i;
                    while (i + 1 < text.length() && Character.isLetter(text.charAt(i + 1))) ++i;
                    String literal = text.substring(start, i + 1);
                    if (!literal.equals("true") && !literal.equals("false") && !literal.equals("null"))
                        throw invalid("JSON literals must be true, false or null");
                }
            }
        }
    }

    private static void validateValue(Object value, Set<String> saved) throws Exception {
        if (value instanceof JSONObject) reference(value, saved);
        if (value instanceof JSONArray) {
            JSONArray array = (JSONArray)value;
            for (int i = 0; i < array.length(); ++i) validateValue(array.get(i), saved);
        }
    }
    private static String reference(Object value, Set<String> saved) throws Exception {
        JSONObject ref = object(value, "reference");
        fields(ref, "ref");
        String name = string(ref, "ref");
        if (!saved.contains(name)) throw invalid("ref must name an earlier saved return value: " + name);
        return name;
    }
    private static JSONObject object(Object value, String name) {
        if (!(value instanceof JSONObject)) throw invalid(name + " must be a JSON object");
        return (JSONObject)value;
    }
    private static String string(JSONObject object, String key) throws Exception {
        Object value = object.get(key);
        if (!(value instanceof String) || ((String)value).isEmpty() || ((String)value).length() > 256)
            throw invalid(key + " must be a nonempty string of at most 256 characters");
        return (String)value;
    }
    private static void fields(JSONObject object, String... allowed) {
        Iterator<String> keys = object.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            boolean found = false;
            for (String expected : allowed) if (key.equals(expected)) { found = true; break; }
            if (!found) throw invalid("unknown JSON field: " + key);
        }
    }

    private static Class<?> type(String name, ClassLoader loader) throws Exception {
        if (name.startsWith("[")) throw invalid("use Java array types such as int[], not JVM descriptors");
        if (name.endsWith("[]")) {
            if (name.length() - name.replace("[]", "").length() > 16) throw invalid("at most 8 array dimensions");
            return Array.newInstance(type(name.substring(0, name.length() - 2), loader), 0).getClass();
        }
        switch (name) {
            case "boolean": return boolean.class;
            case "byte": return byte.class;
            case "short": return short.class;
            case "char": return char.class;
            case "int": return int.class;
            case "long": return long.class;
            case "float": return float.class;
            case "double": return double.class;
            case "void": throw invalid("void is not a parameter/class type");
            default: return Class.forName(name, false, loader);
        }
    }
    private static Class<?> box(Class<?> type) {
        if (type == boolean.class) return Boolean.class;
        if (type == byte.class) return Byte.class;
        if (type == short.class) return Short.class;
        if (type == char.class) return Character.class;
        if (type == int.class) return Integer.class;
        if (type == long.class) return Long.class;
        if (type == float.class) return Float.class;
        if (type == double.class) return Double.class;
        return type;
    }

    private static Object convert(Class<?> type, Object value, Map<String, Object> refs) throws Exception {
        Class<?> boxed = box(type);
        if (value instanceof JSONObject) {
            value = refs.get(((JSONObject)value).getString("ref"));
            if (value == null ? !type.isPrimitive() : boxed.isInstance(value)) return value;
            throw invalid("ref is incompatible with parameter type " + type.getName());
        }
        if (value == JSONObject.NULL) {
            if (type.isPrimitive()) throw invalid("null cannot be passed to " + type.getName());
            return null;
        }
        if (type.isArray()) {
            if (!(value instanceof JSONArray)) throw invalid("array parameter requires a JSON array");
            JSONArray items = (JSONArray)value;
            Class<?> component = type.getComponentType();
            Object array = Array.newInstance(component, items.length());
            for (int i = 0; i < items.length(); ++i) Array.set(array, i, convert(component, items.get(i), refs));
            return array;
        }
        if (boxed == Boolean.class && value instanceof Boolean) return value;
        if (boxed == Character.class && value instanceof String && ((String)value).length() == 1)
            return ((String)value).charAt(0);
        if (boxed == Byte.class || boxed == Short.class || boxed == Integer.class || boxed == Long.class) {
            String text = value instanceof NumberToken ? ((NumberToken)value).text :
                boxed == Long.class && value instanceof String ? (String)value : null;
            if (text == null) throw invalid("integer parameter requires a JSON number (long also accepts a decimal string)");
            BigDecimal number = new BigDecimal(text);
            long min = boxed == Byte.class ? Byte.MIN_VALUE : boxed == Short.class ? Short.MIN_VALUE :
                boxed == Integer.class ? Integer.MIN_VALUE : Long.MIN_VALUE;
            long max = boxed == Byte.class ? Byte.MAX_VALUE : boxed == Short.class ? Short.MAX_VALUE :
                boxed == Integer.class ? Integer.MAX_VALUE : Long.MAX_VALUE;
            if (number.compareTo(BigDecimal.valueOf(min)) < 0 || number.compareTo(BigDecimal.valueOf(max)) > 0)
                throw invalid("integer outside " + type.getName() + " range");
            long integer = number.longValueExact();
            if (boxed == Byte.class) return (byte)integer;
            if (boxed == Short.class) return (short)integer;
            if (boxed == Integer.class) return (int)integer;
            return integer;
        }
        if ((boxed == Float.class || boxed == Double.class) && value instanceof NumberToken) {
            String text = ((NumberToken)value).text;
            if (boxed == Float.class) {
                float number = Float.parseFloat(text);
                if (Float.isInfinite(number) || Float.isNaN(number)) throw invalid("float must be finite and in range");
                return number;
            }
            double number = Double.parseDouble(text);
            if (Double.isInfinite(number) || Double.isNaN(number)) throw invalid("double must be finite and in range");
            return number;
        }
        if ((value instanceof String || value instanceof Boolean) && boxed.isInstance(value)) return value;
        throw invalid("value incompatible with " + type.getName() + "; objects require null or {ref:...}");
    }

    private static Method method(Class<?> owner, String name, Class<?>[] types) throws NoSuchMethodException {
        try { return owner.getDeclaredMethod(name, types); }
        catch (NoSuchMethodException absent) {
            try { return owner.getMethod(name, types); } // Public inherited/interface methods.
            catch (NoSuchMethodException inherited) {
                for (Class<?> parent = owner.getSuperclass(); parent != null; parent = parent.getSuperclass()) {
                    try { return parent.getDeclaredMethod(name, types); }
                    catch (NoSuchMethodException ignored) { }
                }
                throw absent;
            }
        }
    }
    private static IllegalArgumentException invalid(String message) { return new IllegalArgumentException(message); }
}
