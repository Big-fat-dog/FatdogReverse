package com.fatdog.reverse.v;

import java.lang.reflect.Method;

/**
 * L53 焚天火域：那味被换过的配料，末了的一撮火苗压在最后一块砖里。
 *
 * 这个类不在 r8.pro 的白名单里 —— 构建时整个类被 R8 改名，
 * 在 jadx 里搜不到 "Chime" 这个名字。
 *
 * 与 L52 的 Nip 不同：这里的实例**不是 Java 造的**。
 * Bk53 只把本类的 Class 常量递给 native，native 侧用 NewObject
 * 直接调用**私有构造函数**把实例造出来（JNI 不看访问修饰符），
 * 再回调实例方法取件。
 *
 * 真正干活的是私有方法 d()，回调用反射绕过访问修饰符去调它。
 */
public final class Chime {

    /** 实例字段：盐尾段密文（明文 "k53\0" 在任何地方都不出现） */
    private final int[] t;

    /** 实例字段：构造时传入的盐 */
    private final int s;

    /**
     * 私有构造函数 —— JNI 的 NewObject 与反射都不看访问修饰符。
     * 外部 Java 代码无法直接 new 出本类实例。
     */
    private Chime(int salt) {
        this.s = salt;
        this.t = new int[] { 0xD7, 0x8C, 0xBF, 0x76 };
    }

    /**
     * native 回调入口：盐尾段（含一个 0 字节结尾）。
     * mask 由 so 侧的常量传入 —— 少了它，d() 解出来的是乱码。
     */
    public byte[] chip(int mask) {
        try {
            Method m = Chime.class.getDeclaredMethod("d", int[].class, int.class, int.class);
            m.setAccessible(true);
            return (byte[]) m.invoke(this, t, s, mask);
        } catch (Throwable e) {
            return new byte[0];
        }
    }

    /** 私有解密函数：字节混淆的核心 */
    private byte[] d(int[] c, int salt, int mask) {
        byte[] o = new byte[c.length];
        for (int i = 0; i < c.length; i++) {
            int v = (c[i] - salt - i * 17) & 0xFF;
            o[i] = (byte) (v ^ ((mask >> (i * 8)) & 0xFF));
        }
        return o;
    }
}
