package com.fatdog.reverse;

// 幽冥海 KL11 JNI 桥：libm10.so 最小 patch 靶场。
// guard(input)：if (input == MAGIC) return 1; else return 0;
// answer()：return MAGIC ^ XOR_KEY（十进制提交）。
// patch 方法：nop 掉 guard 里的条件跳转指令，使 guard 恒返回 1。
public class Tu {
    static {
        System.loadLibrary("helix");
    }

    private Tu() {
    }

    // guard 函数：传入 0，patch 后恒返回 1。
    public static native int nativeGuard(int input);

    // answer 函数：返回 MAGIC ^ XOR_KEY（十进制）。
    public static native int nativeAnswer();
}
