package com.fatdog.reverse;

// 诱饵：名字起眼但没有任何调用方（假标记与真标记一字之差）
public class Sd {
    public static final String FAKE_KEY = "Fatdog_bolt";

    private Sd() {
    }

    static String decoy() {
        return FAKE_KEY;
    }
}
