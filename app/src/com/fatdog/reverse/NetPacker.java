package com.fatdog.reverse;

// 诱饵工具类：假装会"打包表单/拼参数"，但整个类没有任何调用者。
public class NetPacker {
    static final String FAKE_DOG = "snowdog";
    static final String FAKE_KEY = "not_the_form_key";

    static String pack(String... kv) {
        StringBuilder sb = new StringBuilder();
        for (String s : kv) {
            sb.append(s).append('&');
        }
        return sb.toString();
    }
}