package com.fatdog.reverse;

// 关卡 35 的诱饵：近亲假标记（sneak → skulk）。用它派生钥匙构造的请求
// 会被服务器点名 403。真标记只有 Fatdog_sneak——藏在 libl35.so 的 UTF-16 数组里。
public class Kq {
    public static final String FAKE_KEY = "Fatdog_skulk";

    private Kq() {
    }
}
