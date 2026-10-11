package com.fatdog.reverse.u;

import java.lang.reflect.Method;

/**
 * L52 冰封雪域：那把锁芯的另一半齿牙，冻在了一块不起眼的冰棱里。
 *
 * 这个类不在 r8.pro 的白名单里 —— 构建时整个类被 R8 改名，
 * 在 jadx 里搜不到 "Nip" 这个名字。
 *
 * 取件路径（Java 造对象 → native 缓存 → 回调取件）：
 *   Bk52 的构造函数用反射绕过私有构造函数造出本类实例 →
 *   bindHolder(实例) 交给 libmoose.so 存成全局引用 →
 *   so 侧 CallObjectMethod("trim", "(I)[B") 回调取件。
 *
 * 与 L50 的差别：本关密钥是**字节**而非字符串，回调返回 byte[4]，
 * 与 so 侧的头段凑成一把 16 字节的完整钥匙。
 *
 * 真正干活的是私有方法 d()，trim() 用反射绕过访问修饰符去调它。
 */
public final class Nip {

    /** 实例字段：密文（明文 "sm4_" 在任何地方都不出现） */
    private final int[] a;

    /** 实例字段：构造时传入的盐 */
    private final int s;

    /**
     * 私有构造函数 —— JNI 与反射都不看访问修饰符。
     * 外部 Java 代码无法直接 new 出本类实例。
     */
    private Nip(int salt) {
        this.s = salt;
        this.a = new int[] { 0xE8, 0x1C, 0x77, 0xAD };
    }

    /**
     * native 回调入口。
     * mask 由 so 侧的常量传入 —— 少了它，d() 解出来的是乱码。
     */
    public byte[] trim(int mask) {
        try {
            Method m = Nip.class.getDeclaredMethod("d", int[].class, int.class, int.class);
            m.setAccessible(true);
            return (byte[]) m.invoke(this, a, s, mask);
        } catch (Throwable t) {
            return new byte[0];
        }
    }

    /** 私有解密函数：字节混淆的核心 */
    private byte[] d(int[] c, int salt, int mask) {
        byte[] o = new byte[c.length];
        for (int i = 0; i < c.length; i++) {
            int t = (c[i] - salt - i * 13) & 0xFF;
            o[i] = (byte) (t ^ ((mask >> (i * 8)) & 0xFF));
        }
        return o;
    }
}
