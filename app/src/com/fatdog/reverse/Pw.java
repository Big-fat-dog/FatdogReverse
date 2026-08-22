package com.fatdog.reverse;

// 关卡 31 的诱饵：与真密钥一字之差的"近亲"（lonely → lovely），名字也像密钥库。
// 拿它构造的请求会被服务器点名 403。真密钥两截分居 Java 与 native。
public class Pw {
    public static final String FAKE_KEY = "Fatdog_lovely";

    private Pw() {
    }
}
