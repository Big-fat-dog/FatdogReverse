package com.fatdog.reverse;

// 关卡 29 的诱饵：名字像密钥库、值也符合新标记规范，但没有任何调用方——
// 拿它算签名只会得到服务器 403。真密钥在 libl29.so 的异或数组里，
// 而且真身是动态注册的：so 里两个带名字的导出函数全是坑。
public class Yd {
    public static final String FAKE_KEY = "Fatdog_bogus";

    private Yd() {
    }
}
