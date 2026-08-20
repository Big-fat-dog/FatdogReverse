package com.fatdog.reverse;

import java.nio.charset.StandardCharsets;

// SM4 国密分组密码（128 位分组 / 128 位密钥，32 轮）手写实现，教程 GM/T 0002。
// 结构：KSA 用 FK+τ+L' 展开 32 轮密钥 → 每轮 X[i]^L(τ(X[i+1]^X[i+2]^X[i+3]^rk))。
// 公开 API：encrypt(plain, key) / decrypt(cipher, key)，内置 PKCS7 填充，与标准库结果一致。
public class Sm4Core {
    private static final int[] SBOX = {
            0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2,
            0x28, 0xfb, 0x2c, 0x05, 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
            0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4,
            0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
            0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa,
            0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
            0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2,
            0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
            0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b,
            0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
            0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a, 0xd2,
            0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
            0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30,
            0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
            0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45,
            0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
            0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41,
            0x1f, 0x10, 0x5a, 0xd8, 0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
            0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0, 0x89, 0x69, 0x97, 0x4a,
            0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
            0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e,
            0xd7, 0xcb, 0x39, 0x48,
    };
    private static final int[] FK = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};
    private static final int[] CK = {
            0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1,
            0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
            0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1,
            0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41,
            0x484f565d, 0x646b7279,
    };

    private static int rotl(int x, int n) {
        return Integer.rotateLeft(x, n);
    }

    private static int tau(int w) {
        return (SBOX[(w >>> 24) & 0xff] << 24) | (SBOX[(w >>> 16) & 0xff] << 16)
                | (SBOX[(w >>> 8) & 0xff] << 8) | SBOX[w & 0xff];
    }

    private static int pL(int b) {
        return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24);
    }

    private static int pL2(int b) {
        return b ^ rotl(b, 13) ^ rotl(b, 23);
    }

    private static int[] keySchedule(byte[] key) {
        int[] k = new int[36];
        int[] rk = new int[32];
        for (int i = 0; i < 4; i++) {
            k[i] = be(key, i * 4) ^ FK[i];
        }
        for (int i = 0; i < 32; i++) {
            k[i + 4] = k[i] ^ pL2(tau(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]));
            rk[i] = k[i + 4];
        }
        return rk;
    }

    private static int be(byte[] b, int off) {
        return ((b[off] & 0xff) << 24) | ((b[off + 1] & 0xff) << 16)
                | ((b[off + 2] & 0xff) << 8) | (b[off + 3] & 0xff);
    }

    private static void putBe(byte[] out, int off, int v) {
        out[off] = (byte) (v >>> 24);
        out[off + 1] = (byte) (v >>> 16);
        out[off + 2] = (byte) (v >>> 8);
        out[off + 3] = (byte) v;
    }

    private static void cryptBlock(byte[] in, int inOff, byte[] out, int outOff, int[] rk) {
        int[] x = new int[36];
        for (int i = 0; i < 4; i++) {
            x[i] = be(in, inOff + i * 4);
        }
        for (int i = 0; i < 32; i++) {
            x[i + 4] = x[i] ^ pL(tau(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]));
        }
        putBe(out, outOff, x[35]);
        putBe(out, outOff + 4, x[34]);
        putBe(out, outOff + 8, x[33]);
        putBe(out, outOff + 12, x[32]);
    }

    /** PKCS7 填充加密：数据自动补到 16 的倍数。 */
    public static byte[] encrypt(byte[] plain, byte[] key) {
        int[] rk = keySchedule(key);
        int padLen = 16 - plain.length % 16;
        byte[] padded = new byte[plain.length + padLen];
        System.arraycopy(plain, 0, padded, 0, plain.length);
        for (int i = plain.length; i < padded.length; i++) {
            padded[i] = (byte) padLen;
        }
        byte[] out = new byte[padded.length];
        for (int i = 0; i < padded.length; i += 16) {
            cryptBlock(padded, i, out, i, rk);
        }
        return out;
    }

    /** PKCS7 去填充解密：密文必须是 16 的倍数。 */
    public static byte[] decrypt(byte[] cipher, byte[] key) {
        int[] rk = keySchedule(key);
        int[] rkRev = new int[32];
        for (int i = 0; i < 32; i++) {
            rkRev[i] = rk[31 - i];
        }
        byte[] out = new byte[cipher.length];
        for (int i = 0; i < cipher.length; i += 16) {
            cryptBlock(cipher, i, out, i, rkRev);
        }
        int pad = out[out.length - 1] & 0xff;
        byte[] trimmed = new byte[out.length - pad];
        System.arraycopy(out, 0, trimmed, 0, trimmed.length);
        return trimmed;
    }

    public static byte[] encrypt(String plain, String key) {
        return encrypt(plain.getBytes(StandardCharsets.UTF_8), key.getBytes(StandardCharsets.UTF_8));
    }

    public static String encryptHex(String plain, String key) {
        StringBuilder sb = new StringBuilder();
        for (byte b : encrypt(plain, key)) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    public static String decryptStr(String hexCipher, String key) {
        byte[] data = new byte[hexCipher.length() / 2];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) Integer.parseInt(hexCipher.substring(i * 2, i * 2 + 2), 16);
        }
        return new String(decrypt(data, key.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
    }
}