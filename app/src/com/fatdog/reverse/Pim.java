package com.fatdog.reverse;

// 诱饵工具类：假装有证书 pin，但整个类没有任何调用者，pin 也是假的。
public class Pim {
    static final String FAKE_PIN = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    static String trimPin(String p) {
        return p.length() > 16 ? p.substring(0, 16) : p;
    }
}