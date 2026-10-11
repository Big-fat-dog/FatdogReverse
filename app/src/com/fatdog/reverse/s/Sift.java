package com.fatdog.reverse.s;

import java.lang.reflect.Method;

/**
 * L50 幽暗深渊：那把锁的另一半，被寄放在了这间不挂招牌的屋子里。
 *
 * 这个类不在 r8.pro 的白名单里 —— 构建时整个类被 R8 改名，
 * 在 jadx 里搜不到 "Sift" 这个名字。
 *
 * 取件路径（native → Java）：
 *   Bk50 的构造函数用反射绕过私有构造函数造出本类实例 →
 *   bindHolder(实例) 交给 libcrane.so 存成全局引用 →
 *   so 侧 CallObjectMethod("slice", "(I)Ljava/lang/String;") 回调取件。
 *
 * 真正干活的是私有方法 d()，slice() 用反射绕过访问修饰符去调它。
 */
public final class Sift {

    /** 实例字段：密文（明文 "2026" 在任何地方都不出现） */
    private final int[] a;

    /** 实例字段：构造时传入的盐 */
    private final int s;

    /**
     * 私有构造函数 —— JNI 与反射都不看访问修饰符。
     * 外部 Java 代码无法直接 new 出本类实例。
     */
    private Sift(int salt) {
        this.s = salt;
        this.a = new int[] { 0x2E62, 0x2D99, 0x2DC2, 0x2E21 };
    }

    /**
     * native 回调入口。
     * mask 由 so 侧的常量传入 —— 少了它，d() 解出来的是乱码。
     */
    public String slice(int mask) {
        try {
            Method m = Sift.class.getDeclaredMethod("d", int[].class, int.class, int.class);
            m.setAccessible(true);
            return (String) m.invoke(this, a, s, mask);
        } catch (Throwable t) {
            return "ERR_JAVA";
        }
    }

    /** 私有解密函数：字符串混淆的核心 */
    private String d(int[] c, int salt, int mask) {
        char[] o = new char[c.length];
        for (int i = 0; i < c.length; i++) {
            int t = (c[i] - salt - i * 17) & 0xFFFF;
            o[i] = (char) (t ^ ((mask >> (i * 8)) & 0xFF));
        }
        return new String(o);
    }
}
