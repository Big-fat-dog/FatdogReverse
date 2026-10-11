package com.fatdog.reverse.t;

import java.lang.reflect.Method;

/**
 * L51 雷霆山巅：那味被人偷偷换过的配料，只剩最后一撮留在了这张纸上。
 *
 * 这个类不在 r8.pro 的白名单里 —— 构建时整个类被 R8 改名，
 * 在 jadx 里搜不到 "Spool" 这个名字。
 *
 * 与 L50 的 Sift 不同：这里的实例**不是 Java 造的**。
 * Bk51 只把本类的 Class 常量递给 native，native 侧用 NewObject
 * 直接调用**私有构造函数**把实例造出来（JNI 不看访问修饰符），
 * 再回调实例方法取件。
 *
 * 真正干活的是私有方法 d()，回调用反射绕过访问修饰符去调它。
 */
public final class Spool {

    /** 实例字段：盐尾段密文（明文 "salt!" 在任何地方都不出现） */
    private final int[] t;

    /** 实例字段：构造时传入的盐 */
    private final int s;

    /**
     * 私有构造函数 —— JNI 的 NewObject 与反射都不看访问修饰符。
     * 外部 Java 代码无法直接 new 出本类实例。
     */
    private Spool(int salt) {
        this.s = salt;
        this.t = new int[] { 0x3B02, 0x3A9B, 0x3B5A, 0x3B84, 0x3B70 };
    }

    /**
     * native 回调入口：盐尾段。
     * mask 由 so 侧的常量传入 —— 少了它，d() 解出来的是乱码。
     */
    public String tail(int mask) {
        try {
            Method m = Spool.class.getDeclaredMethod("d", int[].class, int.class, int.class);
            m.setAccessible(true);
            return (String) m.invoke(this, t, s, mask);
        } catch (Throwable e) {
            return "ERR_JAVA";
        }
    }

    /** 私有解密函数：字符串混淆的核心 */
    private String d(int[] c, int salt, int mask) {
        char[] o = new char[c.length];
        for (int i = 0; i < c.length; i++) {
            int v = (c[i] - salt - i * 19) & 0xFFFF;
            o[i] = (char) (v ^ ((mask >> (i * 4)) & 0xFF));
        }
        return new String(o);
    }
}
