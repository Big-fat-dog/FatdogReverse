package com.fatdog.reverse.kkl1;

import java.security.MessageDigest;

/**
 * 玄冥渊 · 业务分片其二（1b）——取数签名本体。
 *
 * 独立编译成一个 dex，构建期整体加密后埋进 assets/kkl1/abyss_marrow.bin；
 * 运行时后于 1a 落盘，经双亲委派链（loader1b.parent = loader1a）加载。
 *
 * sign(mark, ts, page) = md5(hex(mark) + "page=N&ts=T")：古典摘要串接，
 * 不是 HMAC；mark 由 so 侧派生，静态翻不出来。
 */
public final class GateKeeper1b {

    public static String sign(byte[] mark, long ts, int page) {
        try {
            StringBuilder hex = new StringBuilder();
            for (byte b : mark) {
                hex.append(String.format("%02x", b & 0xff));
            }
            String payload = hex.toString() + "page=" + page + "&ts=" + ts;
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] out = md.digest(payload.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : out) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private GateKeeper1b() {}
}
