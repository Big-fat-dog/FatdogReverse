package com.fatdog.reverse;

import com.fatdog.reverse.t.Spool;

/**
 * Native大陆 L51 雷霆山巅：JNI 桥（有状态版 · native 侧 NewObject）。
 *
 * 与 L50 的 Bk50 是两种做法：
 *   L50 —— Java 反射把取件器实例造好，再交给 native 缓存（Java 造对象）；
 *   L51 —— Java 只把 Spool 的 **Class 常量** 递给 native，
 *          native 侧用 NewObject 直接调私有构造函数造实例（native 造对象）。
 *
 * 两种做法共用同一条反向链：
 *   libshark.so → GetMethodID → 回调实例方法取件 → 与 so / 辅助 so 片段拼成完整盐。
 *
 * 三个真正干活的方法是**实例 native**：
 *   String nativeEnc(int page, long ts)   — 3DES-EDE-ECB 加密（返回 hex）
 *   String nativeSign(String enc_hex)     — 摘要签名（salt + enc）
 *   String getKeyHint()                   — 密钥提示
 *
 * Flag: FLAG_18_L51{thunder_peak}
 */
public final class Bk51 {

    /** 实例字段：递给 native 的类常量（R8 改名后 Java 侧仍对得上） */
    private final Class<?> src;

    public Bk51() {
        this.src = Spool.class;   // 编译期类常量 → 抗 R8 改名
        bindKeys(this.src);        // 把 Class 递给 native 缓存
    }

    /* ---- 实例 native：JNI 第二参数已是 jobject（shark.cpp 已同步改） ---- */

    public native String nativeEnc(int page, long ts);

    public native String nativeSign(String enc_hex);

    public native String getKeyHint();

    /** 跨层桥的入口：native 缓存住 Spool 的 jclass、构造与回调 methodID */
    private static native void bindKeys(Class<?> holder);

    /* ---- 以下诱饵 native 保持 static，实现在其它 so，勿动 ---- */
    public static native String nativeBucket(int a0);  // quota
    public static native String nativeShed(String a0);  // newt
    public static native String nativeSlink(String a0, int a1);  // weasel
    public static native String nativeLeap(int a0);  // salmon
    public static native String nativeReconcile(String a0);  // audit
    public static native String nativeHaul(String a0, int a1);  // freight
    public static native String nativeRelay(String a0);  // courier
    public static native int nativeCoupon(int a0, int a1);  // bond
}
