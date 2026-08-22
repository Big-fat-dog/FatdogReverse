package com.fatdog.reverse;

// 关卡 28 的诱饵：名字像密钥库、值也符合新标记规范，但没有任何调用方——
// 拿它算签名只会得到服务器 403。真密钥在 libl28.so 的异或数组里。
public class Fk {
    public static final String FAKE_KEY = "Fatdog_silent";

    private Fk() {
    }
}
