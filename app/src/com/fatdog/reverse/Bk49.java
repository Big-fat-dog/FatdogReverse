package com.fatdog.reverse;

import com.fatdog.reverse.m.Warden;

/**
 * Native大陆 L49 迷雾森林：JNI 桥（有状态版 · native 侧 NewObject）。
 *
 * 与 L48 的 Bk48 是两种做法：
 *   L48 —— Bk48 自己用反射把 Grain 实例造好，再交给 native 缓存（Java 造对象）；
 *   L49 —— Bk49 只把 Warden 的 **Class 常量** 递给 native，
 *          native 侧用 NewObject 直接调私有构造函数造实例（native 造对象）。
 *
 * 两种做法共用同一条反向链：
 *   libotter.so → GetMethodID → 回调实例方法取件 → 与 so 内片段拼成完整密钥。
 */
public final class Bk49 {

    /** 实例字段：递给 native 的类常量（R8 改名后 Java 侧仍对得上） */
    private final Class<?> src;

    public Bk49() {
        this.src = Warden.class;   // 编译期类常量 → 抗 R8 改名
        bindKeys(this.src);        // 把 Class 递给 native 缓存
    }

    /* ---- 实例 native：JNI 第二参数已是 jobject（otter.cpp 已同步改） ---- */

    public native String nativeEnc(int page, long ts);

    public native String nativeSign(String enc_hex);

    public native String getKeyHint();

    /** 跨层桥的入口：native 缓存住 Warden 的 jclass 与三个 methodID */
    private static native void bindKeys(Class<?> holder);

    /* ---- 以下诱饵 native 保持 static，实现在其它 so，勿动 ---- */
    public static native String nativeProbe();  // falcon
    public static native String nativeMix(String a0);  // gecko
    public static native String nativeFingerprint(int a0);  // lynx
    public static native String nativeStretch(String a0, int a1);  // hornet
    public static native long nativeAdvance(int a0, int a1);  // payroll
    public static native String nativeRoute(String a0);  // dispatch
    public static native String nativePack(String a0);  // cargo
    public static native String nativeHold(String a0, int a1);  // escrow
    public static native String nativeLattice(String a0);  // quartz
}
