package com.fatdog.reverse;

// 关卡 37b 的 JNI 桥：libink.so 里手工实现的一枚 32 位摘要。
// 骨架眼熟（小端、四轮、常量表），但常量被换过血；载荷含设备串与一次性随机数。
public class Qb {
    static {
        System.loadLibrary("ink");
    }

    private Qb() {
    }

    // 摘要("dev=<dev>|nonce=<nonce>|page=<page>|ts=<ts>")
    public static native String nativeSign(int page, long ts, String nonce, String dev);
}
