package com.fatdog.reverse;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// Frida 关卡 6 的签名核心：密钥右半部分 + HMAC 计算 + 真正的 HTTP 请求都在这。
// 密钥 = Kx.decodePartA() + 本类的 decodePartB()，运行时才拼出来，代码里搜不到完整密钥。
public class Sg {
    static final String BASE = NetHost.httpBase();   // 主机自动选择：模拟器 10.0.2.2 / 真机 127.0.0.1

    static final byte[] PB = {76, 93, 91, 89, 99, 87, 89, 69, 99, 14, 12, 14, 10};

    static String decodePartB() {
        byte[] out = new byte[PB.length];
        for (int i = 0; i < PB.length; i++) {
            out[i] = (byte) (PB[i] ^ 0x3C);
        }
        return new String(out);
    }

    static String buildKey() {
        return Kx.decodePartA() + decodePartB();
    }

    static String sign(int page, long ts) {
        return hmacSha256Hex(buildKey(), "page=" + page + "&ts=" + ts);
    }

    static String hmacSha256Hex(String key, String msg) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256"));
            byte[] d = mac.doFinal(msg.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    static String fetchPage(String base, int page) throws Exception {
        long ts = System.currentTimeMillis() / 1000;
        String url = base + "/api/page?page=" + page + "&ts=" + ts + "&sign=" + sign(page, ts);
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection)
                new java.net.URL(url).openConnection();
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        conn.setRequestMethod("GET");
        int code = conn.getResponseCode();
        java.io.InputStream is = (code == 200) ? conn.getInputStream() : conn.getErrorStream();
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        int n;
        while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
        is.close();
        conn.disconnect();
        if (code != 200) {
            throw new Exception("HTTP " + code + ": " + bos.toString("UTF-8"));
        }
        return bos.toString("UTF-8");
    }
}