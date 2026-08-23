package com.fatdog.reverse;

public class Ku2 {
    static { System.loadLibrary("kunlun2"); }
    private Ku2() {}
    public static native int nativeForge(int seed);
}
