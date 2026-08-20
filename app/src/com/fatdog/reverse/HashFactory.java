package com.fatdog.reverse;

// 诱饵工具类：带盐的"签名"算法，看起来像真业务代码，但没有任何调用者。
public class HashFactory {
    static final String SALT = "decoy_salt_2026";
    static final String FAKE_SIGN = "9f86d081884c7d659a2feaa0c55ad015";

    static String fakeSign(String s) {
        return Integer.toHexString((SALT + s).hashCode());
    }
}