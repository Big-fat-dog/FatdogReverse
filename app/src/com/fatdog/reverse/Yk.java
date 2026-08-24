package com.fatdog.reverse;

// 签名校验对抗的诱饵：近亲假标记（forge → forgo）。用它派生密钥构造的请求
// 一律 403。真正的 HMAC 标记拆在 Wk/Xh 两类的异或数组里；
// 而这一个明文躺在全局区等粗心的猎物上钩。
public class Yk {
    private Yk() {
    }

    public static final String FAKE_KEY = "Fatdog_forgo";
}
