// kl40.cpp —— KL40「星河倒影」（碧落天 · 综合收官卷）
//
// 伴生 so（runtime 侧）。宿主 App 不是 Flutter 运行时，无法执行 libapp.so，
// 因此由本 so 承担"发包瞬间的加密 + 响应解密"。本关是**三原语叠加**：
//
//   请求加密   enc  = AES-256-GCM(KREQ, nonce(12B) || ct || tag(16))    → hex
//   摘要签名   sign = MD5("page=<p>&ts=<t>&enc=<enc>&k=<主标记>")        → 普通 MD5，非 HMAC
//   响应解密   resp = AES-128-CBC(KRESP, iv(16B) || ct)                  → **换了一把钥**
//
//   KREQ  = SHA256("<主标记>|req")        （32 字节 → AES-256）
//   KRESP = SHA256("<主标记>|resp")[:16]  （16 字节 → AES-128）—— 与请求钥不同
//
// 主标记以真实 Flutter 载荷 libapp.so 的对象池为准（哨兵 "FDK40|"），读不到退镜像常量。
// 反调试走**评分制**（3 信号各 1 分，≥2 才判定），判定成立即静默改用诱饵钥（服务端 403）。

#ifndef KL40_HOST_TEST
#include <jni.h>
#endif

#include "mt_rng.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>

#ifndef KL40_HOST_TEST
#include <unistd.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifdef ANDROID
#include <android/log.h>
#define LOG_TAG "kl40"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) printf(__VA_ARGS__)
#endif

// ============================================================
// AES（128 / 256，加密 + 解密）+ GCM + CBC
// ============================================================
namespace aes_ns {

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t RCON[15] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d};

static inline uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }
static inline uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = (uint8_t)(a & 0x80);
        a = (uint8_t)(a << 1);
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

struct Ctx {
    uint8_t rk[240];
    int rounds;

    void expand(const uint8_t* key, int keybits) {
        int Nk = keybits / 32;
        rounds = Nk + 6;
        int total = 4 * (rounds + 1);
        memcpy(rk, key, (size_t)(keybits / 8));
        for (int i = Nk; i < total; i++) {
            uint8_t t[4];
            memcpy(t, rk + (i - 1) * 4, 4);
            if (i % Nk == 0) {
                uint8_t tmp = t[0];
                t[0] = (uint8_t)(SBOX[t[1]] ^ RCON[i / Nk]);
                t[1] = SBOX[t[2]];
                t[2] = SBOX[t[3]];
                t[3] = SBOX[tmp];
            } else if (Nk > 6 && i % Nk == 4) {
                for (int k = 0; k < 4; k++) t[k] = SBOX[t[k]];
            }
            for (int k = 0; k < 4; k++) rk[i * 4 + k] = (uint8_t)(rk[(i - Nk) * 4 + k] ^ t[k]);
        }
    }

    void encryptBlock(const uint8_t in[16], uint8_t out[16]) const {
        uint8_t s[16];
        for (int i = 0; i < 16; i++) s[i] = (uint8_t)(in[i] ^ rk[i]);
        for (int round = 1; round <= rounds; round++) {
            uint8_t t[16];
            for (int c = 0; c < 4; c++)
                for (int r = 0; r < 4; r++)
                    t[c * 4 + r] = SBOX[s[((c + r) % 4) * 4 + r]];
            memcpy(s, t, 16);
            if (round != rounds) {
                for (int c = 0; c < 4; c++) {
                    uint8_t* p = s + c * 4;
                    uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
                    uint8_t x = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
                    p[0] ^= (uint8_t)(x ^ xtime((uint8_t)(a0 ^ a1)));
                    p[1] ^= (uint8_t)(x ^ xtime((uint8_t)(a1 ^ a2)));
                    p[2] ^= (uint8_t)(x ^ xtime((uint8_t)(a2 ^ a3)));
                    p[3] ^= (uint8_t)(x ^ xtime((uint8_t)(a3 ^ a0)));
                }
            }
            for (int i = 0; i < 16; i++) s[i] ^= rk[round * 16 + i];
        }
        memcpy(out, s, 16);
    }

    void decryptBlock(const uint8_t in[16], uint8_t out[16]) const {
        uint8_t s[16];
        memcpy(s, in, 16);
        for (int i = 0; i < 16; i++) s[i] ^= rk[rounds * 16 + i];   // AddRoundKey(last)
        for (int round = rounds - 1; round >= 0; round--) {
            // InvShiftRows
            uint8_t t[16];
            for (int r = 0; r < 4; r++)
                for (int c = 0; c < 4; c++)
                    t[r + 4 * c] = s[r + 4 * ((c - r + 4) % 4)];
            // InvSubBytes
            for (int i = 0; i < 16; i++) s[i] = INV_SBOX[t[i]];
            // AddRoundKey
            for (int i = 0; i < 16; i++) s[i] ^= rk[round * 16 + i];
            // InvMixColumns（末轮之后不做，这里 round 已含最后一轮之后的情况）
            if (round != 0) {
                for (int c = 0; c < 4; c++) {
                    uint8_t* p = s + c * 4;
                    uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
                    p[0] = (uint8_t)(gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3, 9));
                    p[1] = (uint8_t)(gmul(a0, 9) ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13));
                    p[2] = (uint8_t)(gmul(a0,13) ^ gmul(a1, 9) ^ gmul(a2,14) ^ gmul(a3,11));
                    p[3] = (uint8_t)(gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2, 9) ^ gmul(a3,14));
                }
            }
        }
        memcpy(out, s, 16);
    }
};

// ---------------- CBC 解密（iv 由调用方给出） ----------------
static std::string cbcDecrypt(const uint8_t key[16], const uint8_t iv[16],
                              const uint8_t* data, size_t len) {
    Ctx c;
    c.expand(key, 128);
    std::string out;
    out.resize(len);
    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < len; off += 16) {
        uint8_t dec[16];
        c.decryptBlock(data + off, dec);
        for (int i = 0; i < 16; i++) out[off + i] = (char)(dec[i] ^ prev[i]);
        memcpy(prev, data + off, 16);
    }
    return out;
}

// ---------------- GCM ----------------
static void gfMul(uint8_t Z[16], const uint8_t H[16]) {
    uint8_t V[16];
    memcpy(V, H, 16);
    uint8_t z[16];
    memset(z, 0, 16);
    for (int i = 0; i < 128; i++) {
        int bit = (Z[i >> 3] >> (7 - (i & 7))) & 1;
        if (bit) for (int j = 0; j < 16; j++) z[j] ^= V[j];
        int lsb = V[15] & 1;
        for (int j = 15; j > 0; j--) V[j] = (uint8_t)((V[j] >> 1) | ((V[j - 1] & 1) << 7));
        V[0] >>= 1;
        if (lsb) V[0] ^= 0xE1;
    }
    memcpy(Z, z, 16);
}

// 12 字节 nonce；AAD 为空；输出 ct 与 tag
static void gcmEncrypt(const uint8_t* key, int keybits, const uint8_t nonce[12],
                       const uint8_t* pt, size_t len, uint8_t* ct, uint8_t tag[16]) {
    Ctx c;
    c.expand(key, keybits);

    uint8_t zero[16] = {0};
    uint8_t H[16];
    c.encryptBlock(zero, H);

    uint8_t J0[16] = {0};
    memcpy(J0, nonce, 12);
    J0[15] = 0x01;
    uint8_t E0[16];
    c.encryptBlock(J0, E0);

    // CTR
    uint8_t ctr[16];
    memcpy(ctr, J0, 16);
    for (size_t off = 0; off < len; off += 16) {
        for (int i = 15; i >= 12; i--) { if (++ctr[i] != 0) break; }
        uint8_t ks[16];
        c.encryptBlock(ctr, ks);
        size_t n = len - off < 16 ? len - off : 16;
        for (size_t i = 0; i < n; i++) ct[off + i] = (uint8_t)(pt[off + i] ^ ks[i]);
    }

    // GHASH
    uint8_t Y[16];
    memset(Y, 0, 16);
    for (size_t off = 0; off < len; off += 16) {
        uint8_t blk[16] = {0};
        size_t n = len - off < 16 ? len - off : 16;
        for (size_t i = 0; i < n; i++) blk[i] = ct[off + i];
        for (int i = 0; i < 16; i++) Y[i] ^= blk[i];
        gfMul(Y, H);
    }
    uint8_t lb[16] = {0};
    uint64_t clen = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) lb[15 - i] = (uint8_t)((clen >> (i * 8)) & 0xFF);
    for (int i = 0; i < 16; i++) Y[i] ^= lb[i];
    gfMul(Y, H);
    for (int i = 0; i < 16; i++) tag[i] = (uint8_t)(Y[i] ^ E0[i]);
}

} // namespace aes_ns

// ============================================================
// MD5（RFC 1321）—— 本关的摘要原语
// ============================================================
namespace md5_ns {
static inline uint32_t rotl(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

static const uint32_t K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
static const uint8_t S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

struct Ctx {
    uint32_t a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
    uint64_t len = 0;
    uint8_t buf[64] = {0};
    size_t buflen = 0;
};

static void blockOp(Ctx& x, const uint8_t* p) {
    uint32_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] = (uint32_t)p[i*4] | ((uint32_t)p[i*4+1] << 8) |
               ((uint32_t)p[i*4+2] << 16) | ((uint32_t)p[i*4+3] << 24);
    uint32_t A = x.a, B = x.b, C = x.c, D = x.d;
    for (int i = 0; i < 64; i++) {
        uint32_t F; int g;
        if (i < 16)      { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D;          g = (3 * i + 5) % 16; }
        else             { F = C ^ (B | ~D);       g = (7 * i) % 16; }
        F = F + A + K[i] + M[g];
        A = D; D = C; C = B;
        B = B + rotl(F, S[i]);
    }
    x.a += A; x.b += B; x.c += C; x.d += D;
}

static void update(Ctx& x, const uint8_t* data, size_t len) {
    x.len += len;
    size_t off = 0;
    if (x.buflen > 0) {
        size_t need = 64 - x.buflen;
        size_t take = len < need ? len : need;
        memcpy(x.buf + x.buflen, data, take);
        x.buflen += take; off += take;
        if (x.buflen == 64) { blockOp(x, x.buf); x.buflen = 0; }
    }
    while (off + 64 <= len) { blockOp(x, data + off); off += 64; }
    if (off < len) { memcpy(x.buf, data + off, len - off); x.buflen = len - off; }
}

static std::string digest_hex(const std::string& in) {
    Ctx x;
    update(x, reinterpret_cast<const uint8_t*>(in.data()), in.size());
    uint64_t bits = x.len * 8;
    uint8_t pad = 0x80, zero = 0x00;
    update(x, &pad, 1);
    while (x.buflen != 56) update(x, &zero, 1);
    uint8_t lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (uint8_t)((bits >> (8 * i)) & 0xFF);
    update(x, lb, 8);
    uint8_t out[16];
    uint32_t w[4] = {x.a, x.b, x.c, x.d};
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) out[i * 4 + j] = (uint8_t)((w[i] >> (8 * j)) & 0xFF);
    static const char* H = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 16; i++) { s += H[out[i] >> 4]; s += H[out[i] & 0xF]; }
    return s;
}
} // namespace md5_ns

// ============================================================
// SHA-256（密钥派生 + nativeAnswer）
// ============================================================
namespace sha256_ns {
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void digest_raw(const std::string& s, uint8_t out[32]) {
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    std::string msg = s;
    uint64_t bits = (uint64_t)msg.size() * 8;
    msg += (char)0x80;
    while (msg.size() % 64 != 56) msg += (char)0x00;
    for (int i = 7; i >= 0; i--) msg += (char)((bits >> (i * 8)) & 0xFF);

    for (size_t off = 0; off < msg.size(); off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)(uint8_t)msg[off+i*4]<<24)|((uint32_t)(uint8_t)msg[off+i*4+1]<<16)
                 |((uint32_t)(uint8_t)msg[off+i*4+2]<<8)|(uint8_t)msg[off+i*4+3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
            uint32_t s1 = rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
            w[i] = w[i-16]+s0+w[i-7]+s1;
        }
        uint32_t a=h[0],b=h[1],cc=h[2],dd=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
            uint32_t ch=(e&f)^(~e&g);
            uint32_t t1=hh+S1+ch+K[i]+w[i];
            uint32_t S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
            uint32_t mj=(a&b)^(a&cc)^(b&cc);
            uint32_t t2=S0+mj;
            hh=g; g=f; f=e; e=dd+t1; dd=cc; cc=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=cc; h[3]+=dd;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)((h[i] >> 24) & 0xFF);
        out[i*4+1] = (uint8_t)((h[i] >> 16) & 0xFF);
        out[i*4+2] = (uint8_t)((h[i] >>  8) & 0xFF);
        out[i*4+3] = (uint8_t)( h[i]        & 0xFF);
    }
}

static std::string digest_hex(const std::string& s) {
    uint8_t d[32];
    digest_raw(s, d);
    static const char* H = "0123456789abcdef";
    std::string r;
    for (int i = 0; i < 32; i++) { r += H[d[i] >> 4]; r += H[d[i] & 0xF]; }
    return r;
}
} // namespace sha256_ns

// ============================================================
// 主标记：优先从真实 libapp.so 对象池取；失败退镜像常量
// ============================================================
namespace key_store {

// 镜像兜底：主标记 UTF-8 各字节 ^0x55（volatile 防常量折叠，rule 35）
static const volatile uint8_t MIRROR[] = {
    19,52,33,49,58,50,10,39,48,51,57,48,54,33
};

static const char TAG[] = "FDK40|";
static const size_t TAG_LEN = sizeof(TAG) - 1;

static std::string g_master;
static bool g_ready = false;
static bool g_from_payload = false;

static bool locate_payload(std::string& path) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[1024];
    std::string dir;
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, "librig.so")) continue;
        const char* sp = strchr(line, '/');
        if (!sp) break;
        std::string full(sp);
        while (!full.empty() && (full.back() == '\n' || full.back() == '\r')) full.pop_back();
        size_t slash = full.find_last_of('/');
        if (slash == std::string::npos) break;
        dir = full.substr(0, slash);
        break;
    }
    fclose(fp);
    if (dir.empty()) return false;
    path = dir + "/libapp.so";
    return true;
}

static bool read_tag_from_payload(const std::string& path, std::string& out) {
    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) return false;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0 || sz > (long)(64 * 1024 * 1024)) { fclose(fp); return false; }
    std::vector<uint8_t> buf((size_t)sz);
    size_t got = fread(buf.data(), 1, (size_t)sz, fp);
    fclose(fp);
    if (got != (size_t)sz) return false;

    for (size_t i = 0; i + TAG_LEN < got; i++) {
        if (memcmp(&buf[i], TAG, TAG_LEN) != 0) continue;
        size_t s = i + TAG_LEN;
        size_t e = s;
        while (e < got && buf[e] != '|' && buf[e] != 0 && (e - s) < 64) e++;
        if (e <= s || e >= got || buf[e] != '|') continue;
        out.assign(reinterpret_cast<const char*>(&buf[s]), e - s);
        return !out.empty();
    }
    return false;
}

static const std::string& master() {
    if (g_ready) return g_master;
    std::string path, m;
    if (locate_payload(path) && read_tag_from_payload(path, m)) {
        g_master = m;
        g_from_payload = true;
        LOGI("KL40 master taken from Flutter payload object pool");
    } else {
        std::string s;
        for (size_t i = 0; i < sizeof(MIRROR); i++) s += (char)(MIRROR[i] ^ 0x55);
        g_master = s;
        g_from_payload = false;
        LOGI("KL40 payload unavailable, using mirror master");
    }
    g_ready = true;
    return g_master;
}

static bool from_payload() { master(); return g_from_payload; }

// 诱饵主标记（被检出时静默换用，服务端会 403）
static std::string decoy_master() {
    static const volatile uint8_t D[] = {19,52,33,49,58,50,10,48,54,61,58};
    std::string s;
    for (size_t i = 0; i < sizeof(D); i++) s += (char)(D[i] ^ 0x55);
    return s;
}

// 请求钥（AES-256）与响应钥（AES-128）—— 两把不同的钥
static void req_key(const std::string& m, uint8_t out[32]) {
    sha256_ns::digest_raw(m + "|req", out);
}
static void resp_key(const std::string& m, uint8_t out[16]) {
    uint8_t full[32];
    sha256_ns::digest_raw(m + "|resp", full);
    memcpy(out, full, 16);
}

} // namespace key_store

// ============================================================
// 反调试：评分制（>=2 才判定，防单点误报 —— KL19/KL28 教训）
// ============================================================
namespace guard {
static const int THRESHOLD = 2;
static int g_score = -1;

static int score_ptrace() {
#ifdef __linux__
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            long pid = strtol(line + 10, nullptr, 10);
            fclose(f);
            return pid != 0 ? 1 : 0;
        }
    }
    fclose(f);
#endif
    return 0;
}

static int score_maps() {
#ifdef __linux__
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "frida") || strstr(line, "gadget") ||
            strstr(line, "gum-js") || strstr(line, "linjector")) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
#endif
    return 0;
}

static int score_threads() {
#ifdef __linux__
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", getpid());
    DIR* d = opendir(path);
    if (!d) return 0;
    struct dirent* de;
    int hit = 0;
    while ((de = readdir(d)) != nullptr) {
        if (de->d_name[0] == '.') continue;
        char cp[128];
        snprintf(cp, sizeof(cp), "/proc/%d/task/%s/comm", getpid(), de->d_name);
        FILE* f = fopen(cp, "r");
        if (!f) continue;
        char name[64];
        if (fgets(name, sizeof(name), f)) {
            if (strstr(name, "gum-js-loop") || strstr(name, "pool-frida") ||
                strstr(name, "linjector")) hit = 1;
        }
        fclose(f);
        if (hit) break;
    }
    closedir(d);
    return hit;
#else
    return 0;
#endif
}

static int compute() {
    if (g_score >= 0) return g_score;
    int s = score_ptrace() + score_maps() + score_threads();
    g_score = s;
    if (s >= THRESHOLD) LOGI("KL40 guard tripped (score=%d)", s);
    return s;
}
static bool tripped() { return compute() >= THRESHOLD; }
} // namespace guard

// ============================================================
// 加密 / 签名 / 响应解密
// ============================================================

static void make_nonce(uint8_t nonce[12]) {
#ifdef KL40_HOST_TEST
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)i;
#else
    static uint32_t seq = 0;
    seq++;
    uint64_t mix = (uint64_t)time(nullptr) * 1000003ULL ^ ((uint64_t)getpid() << 32) ^ seq;
    for (int i = 0; i < 12; i++) {
        mix = mix * 6364136223846793005ULL + 1442695040888963407ULL;
        nonce[i] = (uint8_t)(mix >> 33);
    }
#endif
}

static std::string active_master() {
    return guard::tripped() ? key_store::decoy_master() : key_store::master();
}

// 请求：enc = hex(nonce(12) || ct || tag(16))
static std::string build_enc(int page, long long ts) {
    char head[64];
    snprintf(head, sizeof(head), "page=%d&ts=%lld", page, ts);
    std::string pt(head);

    uint8_t k[32];
    key_store::req_key(active_master(), k);
    uint8_t nonce[12];
    make_nonce(nonce);

    std::vector<uint8_t> ct(pt.size());
    uint8_t tag[16];
    aes_ns::gcmEncrypt(k, 256, nonce, reinterpret_cast<const uint8_t*>(pt.data()),
                       pt.size(), ct.data(), tag);

    static const char* H = "0123456789abcdef";
    std::string out;
    for (int i = 0; i < 12; i++) { out += H[nonce[i] >> 4]; out += H[nonce[i] & 0xF]; }
    for (uint8_t b : ct) { out += H[b >> 4]; out += H[b & 0xF]; }
    for (int i = 0; i < 16; i++) { out += H[tag[i] >> 4]; out += H[tag[i] & 0xF]; }
    return out;
}

// 签名：普通 MD5 摘要（非 HMAC）
static std::string build_sign(int page, long long ts, const std::string& enc) {
    char head[128];
    snprintf(head, sizeof(head), "page=%d&ts=%lld&enc=%s&k=", page, ts, enc.c_str());
    return md5_ns::digest_hex(std::string(head) + active_master());
}

// 响应解密：**换一把钥**（AES-128-CBC，iv 前置）
static std::string decrypt_resp(const std::string& hexIn) {
    if (hexIn.size() < 32 || hexIn.size() % 32 != 0) return std::string();
    std::vector<uint8_t> raw(hexIn.size() / 2);
    for (size_t i = 0; i < raw.size(); i++) {
        auto val = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int v1 = val(hexIn[i * 2]), v2 = val(hexIn[i * 2 + 1]);
        if (v1 < 0 || v2 < 0) return std::string();
        raw[i] = (uint8_t)((v1 << 4) | v2);
    }
    uint8_t k[16];
    key_store::resp_key(active_master(), k);
    std::string pt = aes_ns::cbcDecrypt(k, raw.data(), raw.data() + 16, raw.size() - 16);
    // 去 PKCS#7
    if (!pt.empty()) {
        uint8_t pad = (uint8_t)pt.back();
        if (pad >= 1 && pad <= 16 && pt.size() >= pad) pt.resize(pt.size() - pad);
    }
    return pt;
}

// nativeAnswer：sha256(str(1000 数和))[:8]，SEED_KL40 = 20280720
static std::string build_answer() {
    return sha256_ns::digest_hex(std::to_string(mt_rng::kl_server_sum(20280720))).substr(0, 8);
}

// ============================================================
// 宿主自测
// ============================================================
#ifdef KL40_HOST_TEST

int main() {
    printf("md5(abc)          = %s\n", md5_ns::digest_hex("abc").c_str());
    printf("expect            = 900150983cd24fb0d6963f7d28e17f72\n");
    printf("master            = %s (from %s)\n", key_store::master().c_str(),
           key_store::from_payload() ? "payload" : "mirror");
    {
        uint8_t k[32];
        key_store::req_key(key_store::master(), k);
        printf("KREQ              = ");
        for (int i = 0; i < 32; i++) printf("%02x", k[i]);
        printf("\n expect           = 29242857cf181d625daae8382d884665f181e93300b765d8f6f4697d290ceb6e\n");
        uint8_t r[16];
        key_store::resp_key(key_store::master(), r);
        printf("KRESP             = ");
        for (int i = 0; i < 16; i++) printf("%02x", r[i]);
        printf("\n expect           = 86eb74c2e8e5e1c3be77f62a6396e6ee\n");
    }
    std::string e1 = build_enc(1, 1787013761LL);
    std::string e2 = build_enc(7, 1700000000LL);
    printf("enc(1,1787013761) = %s\n", e1.c_str());
    printf("expect            = 000102030405060708090a0bfca4e4823b0690e6ae7f0e72f523021cfb493137d5361668ad86cb7bbfbac307efb927b4\n");
    printf("sign(1,1787013761)= %s\n", build_sign(1, 1787013761LL, e1).c_str());
    printf("expect            = d2b77110728e5bb259dd144b8452e021\n");
    printf("enc(7,1700000000) = %s\n", e2.c_str());
    printf("expect            = 000102030405060708090a0bfca4e4823b0090e6ae7f0e72fd24021df84e3736bf1536c49298716578b4be65144212dc\n");
    printf("sign(7,1700000000)= %s\n", build_sign(7, 1700000000LL, e2).c_str());
    printf("expect            = dad4966e3290dc86a60dbf5f96c0bdbd\n");
    printf("answer(KL40)      = %s\n", build_answer().c_str());
    printf("expect            = 82f73d7c\n");
    printf("guard score       = %d (tripped=%d)\n", guard::compute(), (int)guard::tripped());
    return 0;
}

#else  // ---------- JNI ----------

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterMirror_nativeEnc(JNIEnv* env, jclass clz, jint page, jlong ts) {
    (void)clz;
    return env->NewStringUTF(build_enc((int)page, (long long)ts).c_str());
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterMirror_nativeSign(JNIEnv* env, jclass clz, jint page, jlong ts,
                                                 jstring encStr) {
    (void)clz;
    const char* c = encStr ? env->GetStringUTFChars(encStr, nullptr) : "";
    std::string enc(c ? c : "");
    if (encStr && c) env->ReleaseStringUTFChars(encStr, c);
    return env->NewStringUTF(build_sign((int)page, (long long)ts, enc).c_str());
}

// 响应解密：换一把钥（AES-128-CBC）
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterMirror_nativeDecryptRsp(JNIEnv* env, jclass clz, jstring hexStr) {
    (void)clz;
    const char* c = hexStr ? env->GetStringUTFChars(hexStr, nullptr) : "";
    std::string hexIn(c ? c : "");
    if (hexStr && c) env->ReleaseStringUTFChars(hexStr, c);
    return env->NewStringUTF(decrypt_resp(hexIn).c_str());
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterMirror_nativeAnswer(JNIEnv* env, jclass clz) {
    (void)clz;
    return env->NewStringUTF(build_answer().c_str());
}

// 只读自检：只报密码原语、主标记来源与检测评分，不含密钥明文、不判胜
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterMirror_nativeGetStatus(JNIEnv* env, jclass clz) {
    (void)clz;
    char buf[230];
    snprintf(buf, sizeof(buf),
             "密码原语:AES-256-GCM + MD5 + AES-128-CBC(换钥) | 标记:%s | 检测评分:%d/%d",
             key_store::from_payload() ? "载荷" : "镜像兜底",
             guard::compute(), guard::THRESHOLD);
    return env->NewStringUTF(buf);
}

} // extern "C"

#endif
