package com.fatdog.reverse;

// 诱饵工具类：假装是"密钥仓库"，里面是一把假密钥，整个类没人引用。
public class KeyFactory {
    static final String FAKE_KEY = "FAKE_KEY_FOR_DECOYS";
    static final byte[] FAKE_IV = "0123456789abcdef".getBytes();
}