package com.fatdog.reverse;

// SM3 国密杂凑（256 位）手写实现，教程 GM/T 0004：消息填充 → 512 位分组 → 64 轮压缩。
// 公开 API：sm3Hex(byte[]) 返回 64 位小写 hex，与标准库（gmssl、BouncyCastle）输出一致。
public class Sm3Core {
    private static final int[] IV = {0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
                                     0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e};

    private static int rotl(int x, int n) {
        return Integer.rotateLeft(x, n);
    }

    private static int p0(int x) {
        return x ^ rotl(x, 9) ^ rotl(x, 17);
    }

    private static int p1(int x) {
        return x ^ rotl(x, 15) ^ rotl(x, 23);
    }

    private static int ff(int x, int y, int z, int j) {
        return j < 16 ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
    }

    private static int gg(int x, int y, int z, int j) {
        return j < 16 ? (x ^ y ^ z) : ((x & y) | (~x & z));
    }

    public static byte[] digest(byte[] msg) {
        long bitLen = msg.length * 8L;
        int paddedLen = (msg.length + 8) / 64 * 64 + 64;
        byte[] p = new byte[paddedLen];
        System.arraycopy(msg, 0, p, 0, msg.length);
        p[msg.length] = (byte) 0x80;
        for (int i = 0; i < 8; i++) {
            p[paddedLen - 1 - i] = (byte) (bitLen >>> (8 * i));
        }
        int[] v = IV.clone();
        for (int off = 0; off < paddedLen; off += 64) {
            int[] w = new int[68];
            int[] w1 = new int[64];
            for (int i = 0; i < 16; i++) {
                w[i] = ((p[off + i * 4] & 0xff) << 24) | ((p[off + i * 4 + 1] & 0xff) << 16)
                        | ((p[off + i * 4 + 2] & 0xff) << 8) | (p[off + i * 4 + 3] & 0xff);
            }
            for (int i = 16; i < 68; i++) {
                w[i] = p1(w[i - 16] ^ w[i - 9] ^ rotl(w[i - 3], 15)) ^ rotl(w[i - 13], 7) ^ w[i - 6];
            }
            for (int i = 0; i < 64; i++) {
                w1[i] = w[i] ^ w[i + 4];
            }
            int a = v[0], b = v[1], c = v[2], d = v[3], e = v[4], f = v[5], g = v[6], h = v[7];
            for (int j = 0; j < 64; j++) {
                int tj = j < 16 ? 0x79cc4519 : 0x7a879d8a;
                int ss1 = rotl(rotl(a, 12) + e + rotl(tj, j), 7);
                int ss2 = ss1 ^ rotl(a, 12);
                int tt1 = ff(a, b, c, j) + d + ss2 + w1[j];
                int tt2 = gg(e, f, g, j) + h + ss1 + w[j];
                d = c;
                c = rotl(b, 9);
                b = a;
                a = tt1;
                h = g;
                g = rotl(f, 19);
                f = e;
                e = p0(tt2);
            }
            v[0] ^= a; v[1] ^= b; v[2] ^= c; v[3] ^= d;
            v[4] ^= e; v[5] ^= f; v[6] ^= g; v[7] ^= h;
        }
        byte[] out = new byte[32];
        for (int i = 0; i < 8; i++) {
            out[i * 4] = (byte) (v[i] >>> 24);
            out[i * 4 + 1] = (byte) (v[i] >>> 16);
            out[i * 4 + 2] = (byte) (v[i] >>> 8);
            out[i * 4 + 3] = (byte) (v[i]);
        }
        return out;
    }

    public static String sm3Hex(byte[] msg) {
        StringBuilder sb = new StringBuilder();
        for (byte b : digest(msg)) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    public static String sm3Hex(String s) {
        return sm3Hex(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}