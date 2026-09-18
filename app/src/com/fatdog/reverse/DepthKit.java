package com.fatdog.reverse;

// KL45 深渊合璧 的诱饵类：这里放着一把「像那么回事」的钥匙，别认错。
// 真正的密钥不在任何 Java 代码里——它在被搅乱的页面脚本与 native so 中。
public final class DepthKit {
    private DepthKit() {}

    // 诱饵：与真钥一字之差；用它算出的密文服务端一律不收。
    public static final String FAKE_KEY = "Fatdog_deep";

    // 诱饵：一个假签名前缀，真格式并非如此。
    public static String fakeSignPrefix() {
        return "ab45|";
    }
}
