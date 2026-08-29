package com.fatdog.reverse;

// 关卡 28 的 JNI 桥：签名真身在 libl28.so。jadx 只能看到这行声明——
// strings 也搜不到密钥：它以异或数组躺在 .rodata（^0x5C），运行时才解到栈上。
public class Zk {
    static {
        System.loadLibrary("axol");
    }

    // HMAC-SHA256 签名全在 C 里算（消息格式与密钥都不在 Java）
    public static native String nativeSign(int page, long ts);
}
