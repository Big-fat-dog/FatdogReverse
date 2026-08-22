package com.fatdog.reverse;

// 关卡 29 的 JNI 桥：真身经 libl29.so 的 JNI_OnLoad 动态注册绑定——
// 导出表里搜不到任何"正确名字"的静态注册函数，按名 Hook 只会撞上诱饵。
public class Wq {
    static {
        System.loadLibrary("l29");
    }

    // HMAC-SHA256 签名全在 C 里算（真身在无名 static 函数里）
    public static native String nativeSign(int page, long ts);
}
