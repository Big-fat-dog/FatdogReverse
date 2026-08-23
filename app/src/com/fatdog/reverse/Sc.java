package com.fatdog.reverse;

// 关卡 37 的诱饵：动词系假标记（dodge → drift）。用它算出的签名
// 一律 403。真标记 Fatdog_dodge 藏在 libl37.so 的 UTF-16 数组里，
// 而且直接拿标准 SHA256 去对也永远对不上——变体的 IV 被整组换过。
public class Sc {
    public static final String FAKE_KEY = "Fatdog_drift";

    private Sc() {
    }
}
