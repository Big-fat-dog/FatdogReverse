package com.fatdog.reverse;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;

// 关卡 24 核心：服务器证书 SPKI 的 pin 常量 + pin 校验 + 反 Hook 守卫。
// pin 没有明文（每个字节 ^0x5A 还原）；直接把 verify/checkPin Hook 掉放行，
// 守卫计数不涨、结论为假，响应解析前 assertGuard() 会抛"完整性校验失败"。
// 正解是内存换值：Frida Hook realPin() 的返回值，把内置 pin 换成 mitmproxy
// 证书的 SPKI pin，让真实的校验路径照常走完（守卫计数正常，pin 也匹配）。
public class Z24Core {
    // pin 原文：sha256/B3Mk7KMT2PA+BI0tXRk8t8lNdgMYIo70qvZ59BzGpR4= （每字节 ^0x5A）
    static final int[] PINX = {
		41, 50, 59, 104, 111, 108, 117, 24, 105, 23, 49, 109, 17, 23,
		14, 104, 10, 27, 113, 24, 19, 106, 46, 2, 8, 49, 98, 46,
		98, 54, 20, 62, 61, 23, 3, 19, 53, 109, 106, 43, 44, 0,
		111, 99, 24, 32, 29, 42, 8, 110, 103
	};

    // 守卫状态：校验路径每真实走一次 tick+1；校验结论单独记一份。
    static volatile int guardTicks = 0;
    static volatile boolean lastVerdict = false;

    /** 真正的 pin：Frida 的换票点就在这里（替换返回值）。 */
    public static String realPin() {
        byte[] out = new byte[PINX.length];
        for (int i = 0; i < PINX.length; i++) {
            out[i] = (byte) (PINX[i] ^ 0x5A);
        }
        return new String(out);
    }

    /** pin 校验：先 tick 再比较。整个函数被 Hook 掉（原逻辑没执行）时 tick 不涨。 */
    public static boolean checkPin(String candidate) {
        guardTicks++;
        lastVerdict = realPin().equals(candidate);
        return lastVerdict;
    }

    /** 响应解析前调用：校验链被绕过（没 tick 或结论为假）就抛异常。 */
    public static void assertGuard() {
        if (guardTicks == 0 || !lastVerdict) {
            throw new IllegalStateException("完整性校验失败：校验链被篡改");
        }
    }

    /** 计算服务器证书的 SPKI pin：sha256/ + Base64(SHA-256(公钥 DER))。 */
    public static String spkiSha256(X509Certificate cert) throws Exception {
        byte[] der = cert.getPublicKey().getEncoded();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] d = md.digest(der);
        return "sha256/" + android.util.Base64.encodeToString(d, android.util.Base64.NO_WRAP);
    }
}
