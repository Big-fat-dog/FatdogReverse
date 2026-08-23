package com.fatdog.reverse;

public class Ku5 {
    static { System.loadLibrary("kunlun5"); }
    private Ku5() {}
    public static native String nativeClimb(int seed);

    public static String summitKey() {
        int[] pa = {0x46,0x61,0x74,0x64,0x6f,0x67,0x5f};
        StringBuilder sb = new StringBuilder(pa.length);
        for (int v : pa) sb.append((char) v);
        return sb.toString();
    }
}
