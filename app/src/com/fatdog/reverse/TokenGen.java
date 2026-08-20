package com.fatdog.reverse;

import java.security.SecureRandom;

// 诱饵工具类：看起来会生成一次性随机数，但整个类没有任何调用者。
public class TokenGen {
    static final SecureRandom RNG = new SecureRandom();

    static String nonce() {
        byte[] b = new byte[8];
        RNG.nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }
}