package com.fatdog.reverse;

import com.fatdog.reverse.u.Nip;

/**
 * Native大陆 L52 冰封雪域：JNI 桥（有状态版 · Java 反射造实例）。
 *
 * 与 L50/L51 同款跨层思路，但本关的密钥是**字节**而非字符串：
 *   1. 构造函数用**反射**绕过私有构造，造出取件器 com.fatdog.reverse.u.Nip
 *      （该类不在 r8.pro 白名单里，构建时被 R8 改名；类名只以编译期类常量出现，
 *        R8 改名后依然对得上）；
 *   2. bindHolder(实例) 递给 libmoose.so 缓存成全局引用；
 *   3. native 侧加密时回调 trim(int mask) → byte[4] 取 SM4 密钥尾段，
 *      与 libcobra.so 的头段（cb_seed）拼成完整 16 字节钥匙。
 *
 * 改造后导出表只剩 JNI_OnLoad（RegisterNatives 动态注册），
 * .dynsym 里没有 Java_* 供你对号入座 —— 必须跟 JNI_OnLoad 才看得见绑定关系。
 *
 * 真正干活的方法：
 *   nativeEnc(String)         — 实例 native（魔改 SM4 加密，返回 hex）
 *   nativeSign(int, int)      — 实例 native（HMAC-MD5 签名，返回 hex）
 *   nativeRc4Decrypt(String)  — 静态 native，实现在 libcobra.so
 *
 * Flag: FLAG_18_L52{frozen_snowfield}
 */
public final class Bk52 {

    /** 实例字段：反射造出来的取件器（R8 改名类的实例） */
    private final Object holder;

    public Bk52() {
        this.holder = makeHolder();
        bindHolder(this.holder);
    }

    /** 反射绕过私有构造，造出取件器实例（盐由本类给） */
    private static Object makeHolder() {
        try {
            java.lang.reflect.Constructor<Nip> ctor = Nip.class.getDeclaredConstructor(int.class);
            ctor.setAccessible(true);
            return ctor.newInstance(0x5E13);
        } catch (Throwable t) {
            return null;
        }
    }

    /* ---- 实例 native：第二参数已是 jobject（moose.cpp 已按 jobject 实现） ---- */

    public native String nativeEnc(String data);

    public native String nativeSign(int page, int ts);

    /** 跨层桥入口：native 缓存取件器实例 + 回调 methodID */
    private static native void bindHolder(Object holder);

    /* ---- 以下 static native 实现在其它 so（cobra.so 等），勿动 ---- */
    public static native String nativeRc4Decrypt(String data);

    public static native String nativeCatalog(String a0);  // registry
    public static native String nativeProwl(int a0);  // dingo
    public static native String nativeSoar(String a0);  // eagle
    public static native String nativeTrill(int a0, long a1);  // finch
    public static native int nativeMarkup(String a0, int a1);  // retail
    public static native String nativeLedger(String a0);  // banking
    public static native String nativePool(String a0);  // fund
    public static native String nativeBid(int a0, int a1);  // tender

}
