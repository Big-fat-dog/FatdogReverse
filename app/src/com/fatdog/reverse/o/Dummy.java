package com.fatdog.reverse.o;

// 诱饵类：同样会被 R8 混淆，但整个类没有任何调用者，密钥也是假的。
public class Dummy {
    private static final int[] DP = {99, 97, 101, 95, 93, 91, 8, 2, 6};

    static String fakeEncode(String s) {
        return new StringBuilder(s).reverse().toString();
    }

    static byte[] fakeKey() {
        return Encrypt.decodeBytes(DP);
    }
}