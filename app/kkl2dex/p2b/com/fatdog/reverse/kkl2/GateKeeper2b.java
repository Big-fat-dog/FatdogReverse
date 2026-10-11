package com.fatdog.reverse.kkl2;

/**
 * 万剑冢 · 业务第二片（形状校验）。独立编译成单独一个 dex，构建期 AES-128-CBC
 * 加密后埋进 assets，运行时内存加载、不落盘。
 *
 * 本片只负责「形状」：校验取数 seal 是否为 16 字节（即 MD5 / AES-128 密钥的摘要长度），
 * 给玩家一个「密钥形状」的提示。真正的签名在另一片。
 */
public final class GateKeeper2b {

    /** 纯 Java 自校验：seal 是否 16 字节（提示玩家密钥形状 = AES-128 / MD5 摘要长度） */
    public static boolean markLooksValid(byte[] seal) {
        return seal != null && seal.length == 16;
    }

    /** 片号水印。 */
    public static String shard() {
        return "b";
    }
}
