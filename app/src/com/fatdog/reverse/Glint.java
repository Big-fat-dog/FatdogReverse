package com.fatdog.reverse;

// 诱饵：看起来像"引擎指纹校验器"，含一枚与真标记一字之差的假标记，实际无人调用。
// 密钥以 base64 承载：这里的假钥同样是 base64 串，解码后才是诱饵钥（与真钥一字之差）。
public class Glint {
    static final String FAKE_PIN = "RmF0ZG9nX3ByaXNtYQ==";
    static final String FAKE_TAG = "FDK4B|RmF0ZG9nX3ByaXNtYQ==|END";
    static final boolean VERIFY_ENABLED = true;

    static boolean verify(byte[] der) {
        return VERIFY_ENABLED && der != null && der.length > 0;
    }

    private Glint() {
    }
}
