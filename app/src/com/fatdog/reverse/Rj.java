package com.fatdog.reverse;

// 诱饵：长得像关卡 25 的 Java 层签名器（假密钥 + 假 sign），没有任何地方调用。
// 真正的门禁和签名都在 libnative.so 里，jadx 里找不到真密钥——别在 Java 里浪费时间。
public class Rj {
    static final String FAKE_KEY = "fatdemo_fake_key_java";

    public static String fakeSign(int page, long ts) {
        return FAKE_KEY + page + ts;
    }
}
