package com.fatdog.reverse;

// 诱饵工具类：一堆"看起来有用"的哈希变体，但没有任何调用者。
public class Md5Tools {
    static String md5Upper(String s) {
        return HashFactory.fakeSign(s).toUpperCase();
    }

    static String md5WithSalt(String s, String salt) {
        return HashFactory.fakeSign(salt + s);
    }
}