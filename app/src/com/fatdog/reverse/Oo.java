package com.fatdog.reverse;

// 关卡 36 的诱饵：近亲假标记（break → bluff）。用它派生出来的钥匙构造的请求
// 会被服务器点名 403。真标记只有 Fatdog_break——而且真正的 AES 钥匙还藏在
// so 里那个以 == 结尾的 Base64 串后面（Base64 不是加密）。
public class Oo {
    public static final String FAKE_KEY = "Fatdog_bluff";

    private Oo() {
    }
}
