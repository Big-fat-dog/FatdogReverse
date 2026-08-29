package com.fatdog.reverse;

// 幽冥海 KL12 JNI 桥：libm11.so 动态 patch 靶场。
// seal() 内嵌常量 0x1337CAFE，check(val) 校验它。
// Frida hook seal 强制返回正确值即可过——比静态 nop 容易得多。
public class Uk {
    static {
        System.loadLibrary("m11");
    }

    private Uk() {
    }

    // seal 函数：返回内嵌常量 0x1337CAFE。
    public static native int nativeSeal();

    // check 函数：校验 val == 0x1337CAFE。
    public static native int nativeCheck(int val);
}
