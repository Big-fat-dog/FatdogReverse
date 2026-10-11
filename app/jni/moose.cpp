/*
 * libmoose.so — L52 冰封雪域（Native大陆第 5 关）
 *
 * 主入口 · 魔改 SM4-ECB · 跨 so（dlopen libcobra）+ 跨层（回调 Java）双拼装
 *
 * 静态分析视角：
 *   - 导出表只有 JNI_OnLoad（动态注册；类名/方法名/签名全是运行时解出的密文）；
 *   - dlopen 的库名、dlsym 的符号名也全是密文 → 看不到 libcobra.so / cb_seed 之类；
 *   - 算法类 Pillar 落在匿名命名空间，vtable/析构不进 .dynsym。
 *
 * 跨 so + 跨层密钥拼装：
 *   SM4 密钥 = 头段 ← libcobra.so 的 cb_seed()（12 字节）
 *            + 尾段 ← Java（本 so bindHolder 缓存实例 → 回调 trim(int) 取 byte[]）
 *   → enc = SM52(SM4 密钥, "page=N&ts=T")；少任何一段 → 服务端 403。
 *   签名 = HMAC-MD5(密钥, "page=N&ts=T")，密钥整把来自 libcobra 的 cb_mark()。
 *
 * 协议：GET /api/l52?enc=密文&sign=签名&ts=T（秒级 ts）
 * flag：FLAG_18_L52{frozen_snowfield}
 */

#include <jni.h>
#include <string>
#include <cstring>
#include <cstdint>
#include <dlfcn.h>
#include <pthread.h>

/* ============================================================
 * 字符串密文化（掩码走 volatile，防 -O2 常量折叠成明文）
 * ============================================================ */
static std::string decloak(const unsigned char* enc, size_t n, unsigned char mk) {
    std::string out(n, '\0');
    volatile unsigned char m = mk;
    for (size_t i = 0; i < n; i++) out[i] = (char)(enc[i] ^ m);
    return out;
}
#define DK(ARR, MK) decloak((ARR), sizeof(ARR), (unsigned char)(MK))

/* 类名 / 方法名 / 签名 / 回调锚点 / 库名 / dlsym 名 —— 构建期 XOR ^0x57 密文化 */
static const unsigned char B_CLS[] = { 0x34,0x38,0x3A,0x78,0x31,0x36,0x23,0x33,0x38,0x30,0x78,0x25,0x32,0x21,0x32,0x25,0x24,0x32,0x78,0x15,0x3C,0x62,0x65 };  // com/fatdog/reverse/Bk52
static const unsigned char B_M1[] = { 0x39,0x36,0x23,0x3E,0x21,0x32,0x12,0x39,0x34 };  // nativeEnc
static const unsigned char B_G1[] = { 0x7F,0x1B,0x3D,0x36,0x21,0x36,0x78,0x3B,0x36,0x39,0x30,0x78,0x04,0x23,0x25,0x3E,0x39,0x30,0x6C,0x7E,0x1B,0x3D,0x36,0x21,0x36,0x78,0x3B,0x36,0x39,0x30,0x78,0x04,0x23,0x25,0x3E,0x39,0x30,0x6C };  // (Ljava/lang/String;)Ljava/lang/String;
static const unsigned char B_M2[] = { 0x39,0x36,0x23,0x3E,0x21,0x32,0x04,0x3E,0x30,0x39 };  // nativeSign
static const unsigned char B_G2[] = { 0x7F,0x1E,0x1E,0x7E,0x1B,0x3D,0x36,0x21,0x36,0x78,0x3B,0x36,0x39,0x30,0x78,0x04,0x23,0x25,0x3E,0x39,0x30,0x6C };  // (II)Ljava/lang/String;
static const unsigned char B_M4[] = { 0x35,0x3E,0x39,0x33,0x1F,0x38,0x3B,0x33,0x32,0x25 };  // bindHolder
static const unsigned char B_G4[] = { 0x7F,0x1B,0x3D,0x36,0x21,0x36,0x78,0x3B,0x36,0x39,0x30,0x78,0x18,0x35,0x3D,0x32,0x34,0x23,0x6C,0x7E,0x01 };  // (Ljava/lang/Object;)V
static const unsigned char B_CB[] = { 0x23,0x25,0x3E,0x3A };  // trim
static const unsigned char B_GB[] = { 0x7F,0x1E,0x7E,0x0C,0x15 };  // (I)[B
static const unsigned char B_LIB[] = { 0x3B,0x3E,0x35,0x34,0x38,0x35,0x25,0x36,0x79,0x24,0x38 };  // libcobra.so
static const unsigned char B_LIBD[] = { 0x3B,0x3E,0x35,0x25,0x32,0x30,0x3E,0x24,0x23,0x25,0x2E,0x79,0x24,0x38 };  // libregistry.so
static const unsigned char B_D1[] = { 0x34,0x35,0x08,0x24,0x32,0x32,0x33 };  // cb_seed
static const unsigned char B_D2[] = { 0x34,0x35,0x08,0x3A,0x36,0x25,0x3C };  // cb_mark

/* 诱饵标记（明文可见，strings 可抓） */
static const char FAKE_MARK[] = "Fatdog_frost";

// ==================== 魔改 SM4 S 盒（4 处换值） ====================
static uint8_t SM52_SBOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48,
    // 魔改点：偏移 0x3A → 0x7F, 0x7F → 0x3A, 0xB2 → 0xE8, 0xE8 → 0xB2
};

// 静态初始化时执行4处换值
struct Sm52Init {
    Sm52Init() {
        SM52_SBOX[0x3A] = 0x7F;
        SM52_SBOX[0x7F] = 0x3A;
        SM52_SBOX[0xB2] = 0xE8;
        SM52_SBOX[0xE8] = 0xB2;
    }
};
static Sm52Init sm52_init;

// ==================== 魔改 SM4 常量 ====================
static uint32_t SM52_FK[4] = {
    0xa3b1bac6, 0x56aa3350 ^ 0x12345678, 0x677d9197, 0xb27022dc ^ 0x9ABCDEF0
};

// CK 表：标准 CK 循环左移 1 位
static uint32_t SM52_CK[32];

static void init_ck() {
    static const uint32_t STD_CK[32] = {
        0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
        0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
        0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
        0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
        0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
        0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
        0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
        0x10171e25,0x2c333a41,0x484f565d,0x646b7279
    };
    for (int i = 0; i < 32; i++) {
        SM52_CK[i] = (STD_CK[i] << 1) | (STD_CK[i] >> 31);
    }
}

static uint32_t sm52_rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t sm52_tau(uint32_t x) {
    return (SM52_SBOX[(x >> 24) & 0xFF] << 24) |
           (SM52_SBOX[(x >> 16) & 0xFF] << 16) |
           (SM52_SBOX[(x >> 8) & 0xFF] << 8) |
           SM52_SBOX[x & 0xFF];
}

static uint32_t sm52_L(uint32_t x) {
    return x ^ sm52_rotl(x, 2) ^ sm52_rotl(x, 10) ^ sm52_rotl(x, 18) ^ sm52_rotl(x, 24);
}

static uint32_t sm52_L_prime(uint32_t x) {
    return x ^ sm52_rotl(x, 13) ^ sm52_rotl(x, 23);
}

static uint32_t sm52_t(uint32_t x) {
    return sm52_L(sm52_tau(x));
}

static uint32_t sm52_t_prime(uint32_t x) {
    return sm52_L_prime(sm52_tau(x));
}

// ==================== 深层调用栈辅助函数 ====================
static uint32_t k52_sub_bytes(uint32_t x) {
    return sm52_tau(x);
}

static uint32_t k52_sm4_round(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t rk) {
    return a ^ sm52_t(b ^ c ^ d ^ rk);
}

static void k52_key_expand(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t K[4];
    for (int i = 0; i < 4; i++) {
        K[i] = (key[i*4] << 24) | (key[i*4+1] << 16) | (key[i*4+2] << 8) | key[i*4+3];
    }
    K[0] ^= SM52_FK[0]; K[1] ^= SM52_FK[1]; K[2] ^= SM52_FK[2]; K[3] ^= SM52_FK[3];
    for (int i = 0; i < 32; i++) {
        rk[i] = K[0] ^ sm52_t_prime(K[1] ^ K[2] ^ K[3] ^ SM52_CK[i]);
        K[0] = K[1]; K[1] = K[2]; K[2] = K[3]; K[3] = rk[i];
    }
}

static void k52_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[4];
    for (int i = 0; i < 4; i++) {
        X[i] = (in[i*4] << 24) | (in[i*4+1] << 16) | (in[i*4+2] << 8) | in[i*4+3];
    }
    for (int i = 0; i < 32; i += 4) {
        X[0] = k52_sm4_round(X[0], X[1], X[2], X[3], rk[i]);
        X[1] = k52_sm4_round(X[1], X[2], X[3], X[0], rk[i+1]);
        X[2] = k52_sm4_round(X[2], X[3], X[0], X[1], rk[i+2]);
        X[3] = k52_sm4_round(X[3], X[0], X[1], X[2], rk[i+3]);
    }
    for (int i = 0; i < 4; i++) {
        out[i*4]   = (X[3-i] >> 24) & 0xFF;
        out[i*4+1] = (X[3-i] >> 16) & 0xFF;
        out[i*4+2] = (X[3-i] >> 8) & 0xFF;
        out[i*4+3] = X[3-i] & 0xFF;
    }
}

// ==================== Pillar 类（匿名命名空间：类名/vtable 不进 .dynsym） ====================
namespace {

class Pillar {
public:
    uint32_t rk_[32];
    bool loaded_;

    Pillar() : loaded_(false) {}

    void load(const uint8_t key[16]) {
        k52_key_expand(key, rk_);
        loaded_ = true;
    }

    std::string mint(const std::string& data) {
        if (!loaded_) return "";
        size_t pad_len = 16 - (data.size() % 16);
        std::string padded = data + std::string(pad_len, (char)pad_len);
        std::string out(padded.size(), '\0');
        for (size_t i = 0; i < padded.size(); i += 16) {
            uint8_t enc[16];
            k52_encrypt_block(reinterpret_cast<const uint8_t*>(padded.c_str() + i), enc, rk_);
            memcpy(&out[i], enc, 16);
        }
        return out;
    }
};

} /* anonymous namespace */

// ==================== HMAC-SHA256 ====================
static uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t sha256_h0[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
};

static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    for (int i = 0; i < 16; i++) {
        W[i] = (block[i*4] << 24) | (block[i*4+1] << 16) | (block[i*4+2] << 8) | block[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(W[i-15], 7) ^ rotr32(W[i-15], 18) ^ (W[i-15] >> 3);
        uint32_t s1 = rotr32(W[i-2], 17) ^ rotr32(W[i-2], 19) ^ (W[i-2] >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + sha256_k[i] + W[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static std::string sha256_hash(const std::string& msg) {
    uint32_t state[8];
    memcpy(state, sha256_h0, sizeof(state));
    uint64_t bit_len = msg.size() * 8;
    std::string padded = msg;
    padded += (char)0x80;
    while (padded.size() % 64 != 56) padded += (char)0x00;
    for (int i = 7; i >= 0; i--) padded += (char)((bit_len >> (i * 8)) & 0xFF);
    for (size_t i = 0; i < padded.size(); i += 64) {
        uint8_t block[64];
        memcpy(block, padded.c_str() + i, 64);
        sha256_compress(state, block);
    }
    std::string result(32, '\0');
    for (int i = 0; i < 8; i++) {
        result[i*4]   = (state[i] >> 24) & 0xFF;
        result[i*4+1] = (state[i] >> 16) & 0xFF;
        result[i*4+2] = (state[i] >> 8) & 0xFF;
        result[i*4+3] = state[i] & 0xFF;
    }
    return result;
}

/* ============================================================
 * MD5（供 HMAC-MD5 使用；SHA-256 仍负责 body 摘要）
 * 注意：MD5 是小端（长度字段亦为小端），与 SHA-256 的大端相反
 * ============================================================ */
static const unsigned int md5_k[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

static const unsigned char md5_s[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

#define MD5_ROTL(x,n) (((x)<<(n))|((x)>>(32-(n))))

static void md5_block(unsigned int h[4], const unsigned char *p) {
    unsigned int a=h[0], b=h[1], c=h[2], d=h[3];
    unsigned int m[16], f, g, tmp, i;
    for (i = 0; i < 16; i++)
        m[i] = (unsigned int)p[4*i] | ((unsigned int)p[4*i+1] << 8) |
               ((unsigned int)p[4*i+2] << 16) | ((unsigned int)p[4*i+3] << 24);
    for (i = 0; i < 64; i++) {
        if (i < 16)      { f = (b & c) | ((~b) & d); g = i; }
        else if (i < 32) { f = (d & b) | ((~d) & c); g = (5*i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d;            g = (3*i + 5) & 15; }
        else             { f = c ^ (b | (~d));       g = (7*i) & 15; }
        tmp = d; d = c; c = b;
        b = b + MD5_ROTL(a + f + md5_k[i] + m[g], md5_s[i]);
        a = tmp;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
}

static void md5_digest(const unsigned char *msg, size_t len, unsigned char out[16]) {
    unsigned int h[4];
    size_t off, rem, tlen, i;
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x67452301; h[1]=0xefcdab89; h[2]=0x98badcfe; h[3]=0x10325476;
    for (off = 0; off + 64 <= len; off += 64)
        md5_block(h, msg + off);
    rem = len - off;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    /* 长度字段：64 位小端（MD5 规定，勿照抄 SHA-256 的大端写法） */
    for (i = 0; i < 8; i++)
        tail[tlen - 8 + i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    md5_block(h, tail);
    if (tlen == 128) md5_block(h, tail + 64);
    for (i = 0; i < 4; i++) {
        out[4*i]   = (unsigned char)(h[i] & 0xFF);
        out[4*i+1] = (unsigned char)((h[i] >> 8) & 0xFF);
        out[4*i+2] = (unsigned char)((h[i] >> 16) & 0xFF);
        out[4*i+3] = (unsigned char)((h[i] >> 24) & 0xFF);
    }
}

/* HMAC-MD5：消息不超过 256 字节 */
static void hmac_md5(const unsigned char *key, size_t klen,
                     const unsigned char *msg, size_t mlen,
                     unsigned char out[16]) {
    unsigned char k0[64], ipad[64], opad[64], ih[16], buf[384];
    size_t i;
    memset(k0, 0, sizeof(k0));
    if (klen > 64) md5_digest(key, klen, k0);
    else memcpy(k0, key, klen);
    for (i = 0; i < 64; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    if (mlen > 256) mlen = 256;
    memcpy(buf, ipad, 64);
    memcpy(buf + 64, msg, mlen);
    md5_digest(buf, 64 + mlen, ih);
    memcpy(buf, opad, 64);
    memcpy(buf + 64, ih, 16);
    md5_digest(buf, 80, out);
}

/* HMAC-MD5（std::string 版，与 hmac_sha256 同款结构，仅换摘要原语） */
static std::string md5_hash(const std::string& in) {
    unsigned char d[16];
    md5_digest(reinterpret_cast<const unsigned char*>(in.data()), in.size(), d);
    return std::string(reinterpret_cast<const char*>(d), 16);
}

static std::string hmac_md5(const std::string& key, const std::string& msg) {
    std::string k = key;
    if (k.size() > 64) k = md5_hash(k);
    while (k.size() < 64) k += '\0';
    std::string ipad(64, 0x36), opad(64, 0x5C);
    for (int i = 0; i < 64; i++) { ipad[i] ^= k[i]; opad[i] ^= k[i]; }
    return md5_hash(opad + md5_hash(ipad + msg));
}

static std::string hmac_sha256(const std::string& key, const std::string& msg) {
    std::string k = key;
    if (k.size() > 64) k = sha256_hash(k);
    while (k.size() < 64) k += '\0';
    std::string ipad(64, 0x36), opad(64, 0x5C);
    for (int i = 0; i < 64; i++) { ipad[i] ^= k[i]; opad[i] ^= k[i]; }
    return sha256_hash(opad + sha256_hash(ipad + msg));
}

// ==================== 密钥拼装（跨 so + 跨层） ====================
/* 本地兜底：SM4 头段（"Fatdog_snow_" ^0x3C，12 字节）—— 与 libcobra 的 cb_seed 同源 */
static const uint8_t K52_SM4_HEAD_XOR[] = {
    0x7A,0x5D,0x48,0x58,0x53,0x5B,0x63,0x4F,0x52,0x53,0x4B,0x63
};
/* 本地兜底：签名密钥（"Fatdog_snow_key!" ^0x3C，16 字节） */
static const uint8_t K52_MARK_XOR[] = {
    0x7A,0x5D,0x48,0x58,0x53,0x5B,0x63,0x4F,
    0x52,0x53,0x4B,0x63,0x57,0x59,0x45,0x1D
};
static const uint8_t K52_XOR = 0x3C;

typedef const uint8_t* (*get_key_func)();

/* 从辅助 so 取一段密钥（库名/符号名均来自密文表） */
static std::string get_blob_from_so(const std::string& so_name, const std::string& func_name, int n) {
    void* handle = dlopen(so_name.c_str(), RTLD_NOW);
    if (!handle) return std::string();
    get_key_func fn = (get_key_func)dlsym(handle, func_name.c_str());
    if (!fn) { dlclose(handle); return std::string(); }
    const uint8_t* raw = fn();
    if (!raw) { dlclose(handle); return std::string(); }
    std::string key(reinterpret_cast<const char*>(raw), (size_t)n);
    dlclose(handle);
    return key;
}

/* 签名密钥：整把来自 libcobra 的 cb_mark()，取不到则本地兜底 */
static std::string get_mark_key() {
    std::string key = get_blob_from_so(DK(B_LIB, 0x57), DK(B_D2, 0x57), 16);
    if (key.size() == 16) return key;
    std::string fb(16, '\0');
    volatile uint8_t m = K52_XOR;
    for (int i = 0; i < 16; i++) fb[i] = (char)(K52_MARK_XOR[i] ^ m);
    return fb;
}

// ==================== JNI 函数（静态命名 → RegisterNatives 动态绑定） ====================
static JavaVM* g_jvm = nullptr;

/* ---------- 跨层回调：SM4 密钥尾段（"sm4_"）由 Java 侧供给 ---------- */
static jobject g_obj = NULL;
static jmethodID g_tail = NULL;

/* so 侧常量掩码：Java 侧少一个比特，解出来的就是乱码 */
static const jint K52_MASK = 0x2C7E91A6;

static JNIEnv* cur_env() {
    if (g_jvm == NULL) return NULL;
    JNIEnv* env = NULL;
    if (g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return NULL;
    return env;
}

/* 回调 Java 实例方法 trim(int mask) → byte[4]（本 so 缓存了实例的全局引用） */
static std::string fetch_tail(JNIEnv* env) {
    if (env == NULL) env = cur_env();
    if (env == NULL || g_obj == NULL || g_tail == NULL) return std::string();
    jbyteArray ja = (jbyteArray) env->CallObjectMethod(g_obj, g_tail, K52_MASK);
    if (ja == NULL) return std::string();
    jsize n = env->GetArrayLength(ja);
    jbyte* b = env->GetByteArrayElements(ja, NULL);
    std::string out;
    if (b != NULL && n > 0) {
        out.assign(reinterpret_cast<const char*>(b), (size_t)n);
        env->ReleaseByteArrayElements(ja, b, JNI_ABORT);
    }
    env->DeleteLocalRef(ja);
    return out;
}

/* 拼齐 16 字节 SM4 主密钥：头段 12B（cobra 或本地兜底）+ 尾段 4B（Java） */
static std::string sm4_key(JNIEnv* env) {
    std::string head = get_blob_from_so(DK(B_LIB, 0x57), DK(B_D1, 0x57), 12);
    if (head.size() != 12) {
        std::string fb(12, '\0');
        volatile uint8_t m = K52_XOR;
        for (int i = 0; i < 12; i++) fb[i] = (char)(K52_SM4_HEAD_XOR[i] ^ m);
        head = fb;
    }
    std::string tail = fetch_tail(env);
    if (tail.size() != 4) return std::string();
    return head + tail;
}

static jstring nativeEncImpl(JNIEnv* env, jobject, jstring data) {
    const char* cdata = env->GetStringUTFChars(data, nullptr);
    std::string input = (cdata != nullptr) ? std::string(cdata) : std::string();
    if (cdata != nullptr) env->ReleaseStringUTFChars(data, cdata);

    std::string key = sm4_key(env);
    if (key.size() != 16) return env->NewStringUTF("");

    Pillar cipher;
    cipher.load(reinterpret_cast<const uint8_t*>(key.c_str()));
    std::string enc = cipher.mint(input);

    std::string hex_enc;
    for (unsigned char c : enc) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", c);
        hex_enc += buf;
    }
    return env->NewStringUTF(hex_enc.c_str());
}

static jstring nativeSignImpl(JNIEnv* env, jobject, jint page, jint ts) {
    std::string payload = "page=" + std::to_string(page) + "&ts=" + std::to_string(ts);
    std::string sig = hmac_md5(get_mark_key(), payload);
    std::string hex_sig;
    for (unsigned char c : sig) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", c);
        hex_sig += buf;
    }
    return env->NewStringUTF(hex_sig.c_str());
}

/* 跨层桥：Bk52 反射造出的取件器实例交进来，本 so 缓存成全局引用 + methodID */
static void implBind(JNIEnv* env, jclass, jobject holder) {
    if (g_obj != NULL) { env->DeleteGlobalRef(g_obj); g_obj = NULL; }
    g_tail = NULL;
    if (holder == NULL) return;
    g_obj = env->NewGlobalRef(holder);
    if (g_obj == NULL) return;
    jclass local = env->GetObjectClass(holder);
    if (local == NULL) return;
    std::string cb = DK(B_CB, 0x57);
    std::string gb = DK(B_GB, 0x57);
    g_tail = env->GetMethodID(local, cb.c_str(), gb.c_str());
    env->DeleteLocalRef(local);
}

/* 诱饵导出：Java 侧根本没声明这个方法 —— 纯误导 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk52_nativeMoose(JNIEnv* env, jclass) {
    return env->NewStringUTF(FAKE_MARK);
}

// ==================== RegisterNatives 动态绑定 ====================
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_jvm = vm;
    init_ck();
    JNIEnv* env = cur_env();
    if (env != NULL) {
        std::string cls = DK(B_CLS, 0x57);
        jclass c = env->FindClass(cls.c_str());
        if (c != NULL) {
            std::string n1 = DK(B_M1, 0x57), g1 = DK(B_G1, 0x57);
            std::string n2 = DK(B_M2, 0x57), g2 = DK(B_G2, 0x57);
            std::string n3 = DK(B_M4, 0x57), g3 = DK(B_G4, 0x57);
            JNINativeMethod m[3];
            m[0].name = const_cast<char*>(n1.c_str()); m[0].signature = const_cast<char*>(g1.c_str()); m[0].fnPtr = (void*)nativeEncImpl;
            m[1].name = const_cast<char*>(n2.c_str()); m[1].signature = const_cast<char*>(g2.c_str()); m[1].fnPtr = (void*)nativeSignImpl;
            m[2].name = const_cast<char*>(n3.c_str()); m[2].signature = const_cast<char*>(g3.c_str()); m[2].fnPtr = (void*)implBind;
            if (env->RegisterNatives(c, m, 3) != JNI_OK && env->ExceptionCheck())
                env->ExceptionClear();
        } else if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
    }
    /* 干扰 so：仅 dlopen 进进程（/proc/self/maps 可见、dlopen-trace 可捕获），不 dlsym 不调用 */
    std::string decoy = DK(B_LIBD, 0x57);
    (void)dlopen(decoy.c_str(), RTLD_NOW);
    return JNI_VERSION_1_6;
}
