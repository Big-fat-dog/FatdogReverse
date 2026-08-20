package com.fatdog.reverse.o;

// 关卡 19 密钥/字符串仓库：所有敏感串（算法名、接口路径、三把密钥）都以异或字节数组藏着，
// 运行时经 Encrypt.decodeStr/decodeBytes 还原。本包会被 R8 混淆。
public class Keys {
    // ^0x33：AES/ECB/PKCS5Padding、HmacSHA256、/api/l19
    private static final int[] Q_AES = {114, 118, 96, 28, 118, 112, 113, 28, 99, 120, 112, 96, 6, 99, 82, 87, 87, 90, 93, 84};
    private static final int[] Q_HMAC = {123, 94, 82, 80, 96, 123, 114, 1, 6, 5};
    private static final int[] Q_PATH = {28, 82, 67, 90, 28, 95, 2, 10};
    // ^0x5A：AES 请求密钥 / HMAC 密钥 / AES 响应密钥
    private static final int[] Q_RK = {60, 59, 46, 62, 63, 55, 53, 5, 59, 63, 41, 49, 63, 35, 107, 99};
    private static final int[] Q_HK = {60, 59, 46, 62, 63, 55, 53, 5, 50, 55, 59, 57, 5, 49, 63, 35};
    private static final int[] Q_SK = {60, 59, 46, 62, 63, 55, 53, 5, 40, 41, 42, 49, 63, 35, 107, 99};

    static String algAes() {
        return Encrypt.decodeStr(Q_AES);
    }

    static String algHmac() {
        return Encrypt.decodeStr(Q_HMAC);
    }

    static String path() {
        return Encrypt.decodeStr(Q_PATH);
    }

    static byte[] aesReqKey() {
        return Encrypt.decodeBytes(Q_RK);
    }

    static byte[] hmacKey() {
        return Encrypt.decodeBytes(Q_HK);
    }

    static byte[] aesRspKey() {
        return Encrypt.decodeBytes(Q_SK);
    }
}