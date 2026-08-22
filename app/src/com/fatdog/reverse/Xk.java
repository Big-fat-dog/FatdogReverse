package com.fatdog.reverse;

// 关卡 30 的诱饵：FAKE_KEY 正好是 so 里槽位 3 那把假钥匙（Fatdog_mute），
// 拿它算签名只会换来 403。真密钥在 libl30.so 的 UTF-16 码元数组里。
public class Xk {
    public static final String FAKE_KEY = "Fatdog_mute";

    private Xk() {
    }
}
