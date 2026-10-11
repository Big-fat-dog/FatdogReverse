package com.fatdog.reverse.k;

import java.lang.reflect.Method;

/**
 * L48 的诱饵：形状与 Grain 一模一样（同样的字段、私有构造函数、反射调私有解密），
 * 但密文是错的 —— 解出来是 "2OZ6" 这种一眼像又不对的东西。
 *
 * 本类不被任何地方引用；R8 关了 shrink，所以它照旧留在 dex 里，
 * 玩家得自己判断到底哪一个才被 Bk48 递给了 native。
 */
public final class Husk {

    private final int[] a;

    private final int s;

    private Husk(int salt) {
        this.s = salt;
        this.a = new int[] { 0x1F67, 0x1FD8, 0x1F8C, 0x1FDD };
    }

    public String half(int mask) {
        try {
            Method m = Husk.class.getDeclaredMethod("d", int[].class, int.class, int.class);
            m.setAccessible(true);
            return (String) m.invoke(this, a, s, mask);
        } catch (Throwable t) {
            return "ERR_JAVA";
        }
    }

    private String d(int[] c, int salt, int mask) {
        char[] o = new char[c.length];
        for (int i = 0; i < c.length; i++) {
            int t = (c[i] - salt - i * 7) & 0xFFFF;
            o[i] = (char) (t ^ ((mask >> (i * 5)) & 0xFF));
        }
        return new String(o);
    }
}
