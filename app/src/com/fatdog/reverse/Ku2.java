package com.fatdog.reverse;

public class Ku2 {
    static { System.loadLibrary("lotus"); }
    private Ku2() {}
    public static native int nativeForge(int seed);
}
