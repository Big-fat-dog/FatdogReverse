package com.fatdog.reverse;

// 幽冥海 KL13 JNI 桥：libm12.so CRC 自校验反 patch 靶场。
// guard(input)：CRC 校验 + 比较双保险；check()：独立校验入口。
// patch 任何指令都会改变 CRC → 校验失败 → 静默返回 0。
public class Ap {
    static {
        System.loadLibrary("mantis");
    }

    private Ap() {
    }

    // guard 函数：CRC 校验 + input == MAGIC 双重验证。
    public static native int nativeGuard(int input);

    // check 函数：独立 CRC 校验入口。
    public static native int nativeCheck();
}
