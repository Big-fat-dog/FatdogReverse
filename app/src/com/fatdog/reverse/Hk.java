package com.fatdog.reverse;

// 关卡 33 的诱饵：名字像密钥库、值也符合新标记规范，但没有任何调用方。
// 真密钥 Fatdog_jealous 在 libl33.so 的 UTF-16 数组里——而且只有代码段
// 通过 CRC 自检时才有效，挂上钩子就会被改成一个字节。
public class Hk {
    public static final String FAKE_KEY = "Fatdog_vain";

    private Hk() {
    }
}
