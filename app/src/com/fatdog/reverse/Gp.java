package com.fatdog.reverse;

// 诱饵：长得像关卡 24 的 pin 校验器，但没有任何地方调用它。
// 静态分析时最容易先翻到这个"假 pin"和"假放行"——谁信谁掉坑。
// 真正的校验在 Z24Core.checkPin，还带反 Hook 守卫。
public class Gp {
    static final String FAKE_PIN = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    // 假的校验：只要长得像 pin 就放行。
    public static boolean fakeVerify(String spki) {
        return spki != null && spki.startsWith("sha256/");
    }
}
