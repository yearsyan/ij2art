package org.ij2art.test;

import java.util.Arrays;

/** Ordinary JNI ABI test. It does not install an ART Hook. */
public final class JniAbi {
    private static native Object[] mixed(boolean z, byte b, char c, short s, int i, long j,
        float f0, double d1, Object o, float f2, int i2, double d3, float f4,
        double d5, float f6, double d7, double d8, Object[] a, float f9, long j2, int i3);
    private native Object[] instance(Object o, double d, int i);
    private static native boolean z(boolean v);
    private static native byte b(byte v);
    private static native char c(char v);
    private static native short s(short v);
    private static native int i(int v);
    private static native long j(long v);
    private static native float f(float v);
    private static native double d(double v);
    private static native Object l(Object v);
    private static native void v();
    private static native void thrown();
    private static native int last(int v);
    private static native long[] pointers();

    private static void check(boolean value) {
        if (!value) throw new AssertionError("JNI ABI mismatch");
    }
    public static void main(String[] args) {
        System.load(args[0]);
        Object object = new Object();
        Object[] array = {"root", object};
        Object[] expected = {true, (byte)-17, '\uffed', (short)-30000, -1234567,
            0x8123456789abcdefL, 1.25f, -2.5d, object, -3.75f, 987654,
            4.125d, 5.5f, -6.25d, 7.75f, 8.875d, -9.5d, array, 10.25f,
            0x7123456789abcdefL, -7654321};
        for (int n = 0; n < 100; n++) {
            Object[] actual = mixed(true, (byte)-17, '\uffed', (short)-30000, -1234567,
                0x8123456789abcdefL, 1.25f, -2.5d, object, -3.75f, 987654,
                4.125d, 5.5f, -6.25d, 7.75f, 8.875d, -9.5d, array, 10.25f,
                0x7123456789abcdefL, -7654321);
            check(Arrays.equals(expected, actual));
            JniAbi receiver = new JniAbi();
            Object[] result = receiver.instance(object, -42.5d, -7);
            check(result[0] == receiver && result[1] == object && result[2].equals(-42.5d)
                  && result[3].equals(-7));
            check(z(true) && !z(false) && b((byte)-128) == -128 && c('\uffff') == '\uffff');
            check(s((short)-32768) == -32768 && i(Integer.MIN_VALUE) == Integer.MIN_VALUE);
            check(j(Long.MIN_VALUE + 123) == Long.MIN_VALUE + 123);
            check(Float.floatToRawIntBits(f(-0.0f)) == 0x80000000);
            check(Double.doubleToRawLongBits(d(-0.0)) == 0x8000000000000000L);
            check(Float.isNaN(f(Float.NaN)) && d(Double.POSITIVE_INFINITY) == Double.POSITIVE_INFINITY);
            check(l(object) == object && l(null) == null);
            v();
            try { thrown(); throw new AssertionError("missing native exception"); }
            catch (IllegalStateException ex) { check("static JNI exception".equals(ex.getMessage())); }
            check(last(-12345) == -12345);
        }
        long[] addresses = pointers();
        check(addresses.length == 128);
        for (int n = 0; n < addresses.length; n++) check(addresses[n] - addresses[0] == n * 12);
        System.out.println("PASS: 128 static JNI slot addresses, first/last slot dispatch, mixed GP/FP spills, instance/static, all Java types, return bits, JNI roots and exceptions (CheckJNI)");
    }
}
