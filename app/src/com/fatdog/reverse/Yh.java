package com.fatdog.reverse;

// 关卡 34 的 JNI 桥：五个方法全部经 libl34.so 的 JNI_OnLoad 动态注册绑定——
// 导出表里只有两个诱饵。enc=Feistel8(Fatdog_grumpy,payload)、sign=HMAC(enc)，
// 响应 {"d":hex} 用 nativeUnwrap 解 RC4；守卫：四路哨兵 + CRC 自校验 + 记账。
public class Yh {
    static {
        System.loadLibrary("l34");
    }

    private Yh() {
    }

    public static native String nativePack(int page, long ts);

    public static native String nativeSign(String enc);

    public static native String nativeUnwrap(String dHex);

    public static native boolean assertGuard(int minTicks);

    public static native int isPoisoned();
}
