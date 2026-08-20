package com.fatdog.reverse;

// 关卡 23 的 H5 路径：下面每个字节 ^ 0x2F 还原出 "/h5/v23"。
// 主机部分由 NetHost 按环境选择（模拟器 10.0.2.2 / 真机 127.0.0.1）。
// 不用 config.json 的基址——这关必须走 HTTPS，证书错误才是剧情本体。
public class Hq {
    private static final int[] C = {0, 71, 26, 0, 89, 29, 28};
    private static final int X = 0x2F;

    static String path() {
        byte[] b = new byte[C.length];
        for (int i = 0; i < C.length; i++) {
            b[i] = (byte) (C[i] ^ X);
        }
        return new String(b);
    }

    public static String url() {
        return NetHost.httpsBase() + path();
    }
}
