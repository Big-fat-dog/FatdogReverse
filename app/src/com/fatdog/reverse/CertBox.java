package com.fatdog.reverse;

// 诱饵工具类：假装有证书/密钥，但整个类没有任何调用者。
public class CertBox {
    static final String FAKE_CA = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----";
    static final String FAKE_KEY = "f4k3k3y!";

    static String wrap(String s) {
        return "[" + s + "]";
    }
}