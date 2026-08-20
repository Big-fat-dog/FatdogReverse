package com.fatdog.reverse;

import android.webkit.WebView;

// 诱饵：长得像关卡 23 的 WebView 工具，但没有任何地方调用它。
// 真正的核心在 y3Activity 的内部类 WvClient 与 Hq 的异或地址里。
public class WvKit {
    public static void setup(WebView web) {
        web.getSettings().setJavaScriptEnabled(false);
        web.getSettings().setBlockNetworkLoads(true);
    }

    public static String fakeGate(int seed) {
        return String.valueOf((seed * 31 + 7) % 100000);
    }

    public static String mistHint() {
        return "证书错误要 cancel，别 proceed。";
    }
}
