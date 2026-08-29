package com.fatdog.reverse;

// 昆仑 KL1 桥：App 本地调用与玩家 unidbg 调用的是同一个导出函数。
public class Ku1 {
    static {
        System.loadLibrary("cedar");
    }

    private Ku1() {
    }

    public static native int klGate(int seed);
}
