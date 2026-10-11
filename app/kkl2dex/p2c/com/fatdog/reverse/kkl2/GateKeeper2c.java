package com.fatdog.reverse.kkl2;

import java.security.MessageDigest;

/**
 * 万剑冢 · 业务第三片（取数签名）。独立编译成单独一个 dex，构建期 AES-128-CBC
 * 加密后埋进 assets，运行时内存加载、不落盘。
 *
 * 本片是「核心」：取数验签逻辑全在这里。sign = MD5( hex(seal) + "page=N&ts=T" )
 * （MD5 古典摘要，非 HMAC），seal 由 libkkl2.so 派生（真标记藏 UTF-16，明文拿不到）。
 *
 * 身份在 2a、形状校验在 2b、签名在 2c——三片各自独立、缺一不可。
 */
public final class GateKeeper2c {

    /** MD5 签名，hex 小写输出：md5( hex(seal) + "page=N&ts=T" ) */
    public static String sign(byte[] seal, long ts, int page) {
        try {
            StringBuilder hex = new StringBuilder();
            for (byte b : seal) {
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

    /** 片号水印。 */
    public static String shard() {
        return "c";
    }
}
