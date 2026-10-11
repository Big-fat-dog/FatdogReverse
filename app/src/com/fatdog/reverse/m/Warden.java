package com.fatdog.reverse.m;

import java.lang.reflect.Method;

/**
 * L49 迷雾森林：岔路口那本册子里，被人撕走了两页。
 *
 * 这个类不在 r8.pro 的白名单里 —— 构建时整个类被 R8 改名，
 * jadx 里搜不到 "Warden" 这个名字。
 *
 * 与 L48 的 Grain 不同：这里的实例**不是 Java 造的**。
 * Bk49 只把本类的 Class 常量递给 native，native 侧用 NewObject
 * 直接调用**私有构造函数**把实例造出来（JNI 不看访问修饰符），
 * 再回调实例方法取件。
 *
 * 真正干活的是私有方法 d()，两个回调都用反射绕过访问修饰符去调它。
 */
public final class Warden {

    /** 实例字段：SM4 尾段密文（明文在任何地方都不出现） */
    private final int[] m;

    /** 实例字段：HMAC 头段密文 */
    private final int[] h;

    /** 实例字段：构造时传入的盐 */
    private final int s;

    /**
     * 私有构造函数 —— JNI 的 NewObject 与反射都不看访问修饰符。
     * 外部 Java 代码无法直接 new 出本类实例。
     */
    private Warden(int salt) {
        this.s = salt;
        this.m = new int[] { 0x2C61, 0x2CA8, 0x2C73, 0x2CDC };
        this.h = new int[] {
            0x2CDD, 0x2C89, 0x2CC2, 0x2C89, 0x2D20, 0x2CBB, 0x2D05,
            0x2CB3, 0x2D4C, 0x2CD4, 0x2D0B, 0x2CD4, 0x2D8F, 0x2CEB
        };
    }

    /**
     * native 回调入口之一：SM4 尾段。
     * mask 由 so 侧的常量传入 —— 少了它，d() 解出来的是乱码。
     */
    public String mistTail(int mask) {
        try {
            Method md = Warden.class.getDeclaredMethod("d", int[].class, int.class);
            md.setAccessible(true);
            int[] o = (int[]) md.invoke(this, m, mask);
            StringBuilder sb = new StringBuilder(o.length);
            for (int v : o) sb.append((char) v);
            return sb.toString();
        } catch (Throwable t) {
            return "ERR_JAVA";
        }
    }

    /**
     * native 回调入口之二：HMAC 头段（以字符码数组返回，交给 native 拼串）。
     */
    public int[] forestHead(int mask) {
        try {
            Method md = Warden.class.getDeclaredMethod("d", int[].class, int.class);
            md.setAccessible(true);
            return (int[]) md.invoke(this, h, mask);
        } catch (Throwable t) {
            return new int[0];
        }
    }

    /** 私有解密函数：字符串混淆的核心 */
    private int[] d(int[] c, int mask) {
        int[] o = new int[c.length];
        for (int i = 0; i < c.length; i++) {
            int b = (mask >>> ((i % 4) * 8)) & 0xFF;
            int t = (c[i] - s - i * 11) & 0xFFFF;
            o[i] = t ^ b;
        }
        return o;
    }
}
