package com.fatdog.reverse;

// 诱饵工具类：里面有一段"AES"密文和一把假密钥，但没人调用它。
public class MiscCrypt {
    static final String FAKE_KEY = "not_the_key_0000";
    static final String FAKE_DATA = "AAAAbbbbCCCCdddd";

    static String scatter(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            sb.append((char) (s.charAt(i) ^ 3));
        }
        return sb.toString();
    }
}