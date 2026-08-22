package com.fatdog.reverse.p;

// 关卡 27 素材库（前半）：算法名/接口路径/证书 pin 与密钥前缀，全部以异或字节数组藏着。
// 三把密钥各拆两半——前缀在本类，后缀在 Tail，运行时才拼出完整密钥。
public class Mk {
    // ^0x31：AES/ECB/PKCS5Padding、HmacSHA256
    static final int[] S_AES = {112, 116, 98, 30, 116, 114, 115, 30, 97, 122, 114, 98, 4, 97, 80, 85, 85, 88, 95, 86};
    static final int[] S_HMAC = {121, 92, 80, 82, 98, 121, 112, 3, 4, 7};
    // ^0x25：/api/l27
    static final int[] S_PATH = {10, 68, 85, 76, 10, 73, 23, 18};
    // ^0x3C：fatdemo_（三把密钥共用前缀）
    static final int[] S_PRE = {90, 93, 72, 88, 89, 81, 83, 99};
    // ^0x27：服务器证书 SPKI pin（无明文 sha256/ 前缀）
    static final int[] S_PIN = {84, 79, 70, 21, 18, 17, 8, 101, 20, 106, 76, 16, 108, 106, 115, 21, 119, 102, 12, 101, 110, 23, 83, 127, 117, 76, 31, 83, 31, 75, 105, 67, 64, 106, 126, 110, 72, 16, 23, 86, 81, 125, 18, 30, 101, 93, 96, 87, 117, 19, 26};

    static String algAes() {
        return Cpt.decodeStr(S_AES, 0x31);
    }

    static String algHmac() {
        return Cpt.decodeStr(S_HMAC, 0x31);
    }

    static String path() {
        return Cpt.decodeStr(S_PATH, 0x25);
    }

    static byte[] pre() {
        return Cpt.decodeBytes(S_PRE, 0x3C);
    }

    static String pin() {
        return Cpt.decodeStr(S_PIN, 0x27);
    }
}
