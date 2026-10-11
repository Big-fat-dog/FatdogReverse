package com.fatdog.reverse;

import com.fatdog.reverse.s.Sift;

import java.lang.reflect.Constructor;

/**
 * Native大陆 L50 幽暗深渊：JNI 桥（有状态版 · Java 反射造实例）。
 *
 * 本关的 native 桥不再是"一堆 static 方法"——L50 的桥是**有状态的**：
 *   1. 构造函数里用**反射**绕过私有构造，造出一个取件器实例
 *      （com.fatdog.reverse.s.Sift —— 该类不在 r8.pro 白名单里，构建时被 R8 改名，
 *        jadx 里搜不到 "Sift" 这个名字；类名只以**编译期类常量**形式出现，
 *        R8 改名后依然对得上）；
 *   2. 把实例经 bindHolder 递给 libcrane.so 缓存成全局引用；
 *   3. native 侧加密时回调该实例的实例方法 slice(int mask) 取 AES 密钥尾段。
 *
 * 三个真正干活的方法是**实例 native**（第二参数是 jobject）：
 *   String nativeEnc(int page, long ts)   — AES-128-ECB 加密（返回 hex）
 *   String nativeSign(String enc_hex)     — SHA-256 签名
 *   String getKeyHint()                   — 密钥提示
 *
 * 破解路线：
 *   ① IDA 打开 libcrane.so：导出表只剩 JNI_OnLoad（没有 Java_* 供你对号入座），
 *      进 JNI_OnLoad 反汇编 → 看它 RegisterNatives 了哪几个名字、签名（全是密文解出）；
 *   ② 顺着 bindHolder → GetMethodID → CallObjectMethod 反查 Java 侧回调目标；
 *   ③ jadx：Bk50 的构造函数里反射造了个 R8 改名类的实例，顺 Sift 找到密文数组 +
 *      私有解密函数；掩码常量在 so 里（K50_MASK），盐在 Bk50 —— 两边都要才解得开；
 *   ④ Frida：hook CallObjectMethod 或直接拿返回值，逐页取数。
 *
 * Flag: FLAG_18_L50{abyssal_depths}
 */
public final class Bk50 {

    /** 实例字段：反射造出来的取件器（R8 改名类的实例） */
    private final Object holder;

    public Bk50() {
        this.holder = makeHolder();
        bindHolder(this.holder);
    }

    /** 反射绕过私有构造，造出取件器实例（盐由本类给） */
    private static Object makeHolder() {
        try {
            Constructor<Sift> ctor = Sift.class.getDeclaredConstructor(int.class);
            ctor.setAccessible(true);
            return ctor.newInstance(0x2D71);
        } catch (Throwable t) {
            return null;
        }
    }

    /* ---- 实例 native：第二参数已是 jobject（crane.cpp 已按 jobject 实现） ---- */

    public native String nativeEnc(int page, long ts);

    public native String nativeSign(String enc_hex);

    public native String getKeyHint();

    /** 跨层桥入口：native 缓存取件器实例 + 回调 methodID */
    private static native void bindHolder(Object holder);

    /* ---- 以下诱饵 native 保持 static，实现在其它 so，勿动 ---- */
    public static native String nativeLadder(int a0);  // ibex
    public static native String nativeWrap(String a0);  // koala
    public static native String nativeFade(String a0, int a1);  // mink
    public static native String nativeChirp(int a0, long a1);  // cricket
    public static native String nativeSettle(String a0);  // invoice
    public static native String nativeBundle(String a0);  // parcel
    public static native int nativeQuote(String a0, int a1);  // vendor
    public static native String nativeIndex(String a0);  // manifest
    public static native String nativeStratum(int a0);  // granite
}
