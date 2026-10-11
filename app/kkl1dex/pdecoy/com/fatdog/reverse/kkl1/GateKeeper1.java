package com.fatdog.reverse.kkl1;

import java.security.MessageDigest;

/**
 * 玄冥渊 · 明文诱饵分片 —— 不做加密，直接以 classes_decoy.dex 躺在 assets 里。
 *
 * 它和真身长得一模一样：同样的包名、同样的方法签名、同样"能跑"。
 * 唯一的差别在那串字面量——那是 so 里 strings 翻得到的明文诱饵，用它派生
 * 出的 mark 到服务端一定被拒。钓的就是"找到一片就收工"的人。
 */
public final class GateKeeper1 {

    /** 诱饵标记：与 so 里明文可见的那串一致（一字之差，非真身） */
    private static final String BAIT = "Fatdog_hollow";
    private static final String SALT = "|kkl1_abyss";

    /** 诱饵身份串：刻意与真身同款，好让只找到这片的人误以为得手 */
    public static String magic() {
        return "XuanMingYuan:GateKeeper1";
    }

    /** 用诱饵标记派生的 mark：客户端自洽，服务端必 403 */
    public static byte[] mark() {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return md.digest((BAIT + SALT).getBytes("UTF-8"));
        } catch (Exception e) {
            return new byte[16];
        }
    }

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

    private GateKeeper1() {}
}
