package com.fatdog.reverse;

// 诱饵：看起来像另一套环境检测器（含一枚假口令），实际无人调用。
// 假口令同样以 base64 承载（解码后为诱饵钥，与真钥一字之差）。
public class Wisp {
    static final String FAKE_KEY = "RmF0ZG9nX2ZvZw==";
    static final int SUSPECT_PORT = 8888;
    static final boolean TAPPED = true;

    static boolean isTapped() {
        return TAPPED;
    }

    private Wisp() {
    }
}
