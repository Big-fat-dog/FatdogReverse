package com.fatdog.reverse;

import java.lang.reflect.Constructor;

import com.fatdog.reverse.k.Grain;

/**
 * Native大陆 L48 落日平原：JNI 桥（有状态版）。
 *
 * 这个桥不再是一堆静态函数：
 *   - 它自己要靠 new 出来（实例化 + 构造函数）；
 *   - 持有实例字段 held —— 那半截密钥真正的载体（Java 对象）；
 *   - 用反射绕过 Grain 的**私有构造函数**把实例造出来，再交给 native 缓存。
 *
 * native 侧（libbadger.so）拿到实例后，在算签名时回调 held.half(mask) 取右半段，
 * 与 so 内的 "Fatdog_calm_" 用 SignKey::operator+ 拼成完整密钥。
 */
public final class Bk48 {

    /** 实例字段：装着半截密钥的 Java 对象（native 会回调它的 half(int)） */
    private final Object held;

    /** 构造时传入 Grain 的盐（与 so 侧的 mask 是两个不同层的常量） */
    private static final int SALT = 0x1F3A;

    public Bk48() {
        Object h;
        try {
            Class<?> c = Grain.class;                                // 编译期类常量 → R8 改名后仍然对得上
            Constructor<?> k = c.getDeclaredConstructor(int.class);  // 拿私有构造函数
            k.setAccessible(true);                                   // 反射绕过访问修饰符
            h = k.newInstance(SALT);                                 // 反射实例化
        } catch (Throwable t) {
            h = null;
        }
        this.held = h;
        bindHolder(this.held);                                       // 把实例递给 native 存全局引用
    }

    /* ---- 实例 native：JNI 第二参数已是 jobject（badger.cpp 已同步改） ---- */

    public native String nativeSign(int page, long ts);

    public native String getKeyHint();

    /** 跨层桥的入口：native 缓存住 holder 的 jclass 与实例 */
    private static native void bindHolder(Object holder);

    /* ---- 以下诱饵 native 保持 static，实现在其它 so，勿动 ---- */
    public static native String nativeAudit();  // heron
    public static native String nativeDigest(String a0);  // pelican
    public static native String nativeToken(int a0);  // magpie
    public static native String nativeChecksum(String a0);  // walrus
    public static native String nativePad(String a0, int a1);  // beetle
    public static native String nativeEnvelope(int a0, long a1);  // ledger
    public static native String nativeSeal(String a0);  // voucher
    public static native int nativeRate(int a0, int a1);  // tariff
    public static native String nativeBlend(String a0);  // cobalt
}
