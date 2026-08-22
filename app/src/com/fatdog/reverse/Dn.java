package com.fatdog.reverse;

// 关卡 32 的诱饵：名字像密钥库、值也符合新标记规范，但没有任何调用方——
// 拿它算签名只会换来 403。真密钥 Fatdog_anxious 在 libl32.so 的 UTF-16 数组里，
// 而且只有"环境干净"时才有效——哨兵一报警就会被改成一个字节。
public class Dn {
    public static final String FAKE_KEY = "Fatdog_tense";

    private Dn() {
    }
}
