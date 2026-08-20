package com.fatdog.reverse;

// 诱饵工具类：假装会做 RSA/DES，但整个类没有任何调用者，密钥也是假的。
public class RsaKit {
    static final String FAKE_N = "00c0ffee00c0ffee";
    static final String FAKE_KEY = "wrongdes!";

    static String fakeRsaEncrypt(String s) {
        return new StringBuilder(s).reverse().toString();
    }
}