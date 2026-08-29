package com.fatdog.reverse;

// 关卡 33 的 JNI 桥：libl33.so 会对自身代码段做 CRC 自校验（基线建于 JNI_OnLoad），
// 并带记账守卫防整体替换。任何 inline hook 都会被抓——三条官方解法见关卡提示。
public class Fh {
    static {
        System.loadLibrary("sable");
    }

    private Fh() {
    }

    public static native String nativeSign(int page, long ts);

    // 记账守卫：ticks 必须随签名递增且结论为干净——整体替换 nativeSign 会在这里现形
    public static native boolean assertGuard(int minTicks);

    public static native int isPoisoned();
}
