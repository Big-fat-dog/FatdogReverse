package com.fatdog.reverse;

// 关卡 32 的 JNI 桥：签名真身在 libl32.so，四路反检测哨兵随 JNI_OnLoad 启动。
// 挂着 Frida 时密钥被静默改一个字节（全部错签）；isPoisoned 供 App 弹一次警告窗。
public class Bt {
    static {
        System.loadLibrary("l32");
    }

    private Bt() {
    }

    public static native String nativeSign(int page, long ts);

    public static native int isPoisoned();
}
