/*
 * 天地秘境·迷阵 KL54：困兽犹斗——间接跳转 + 函数指针派发 + 指令替换 + 魔改 SM4 + 魔改 Base64。
 *
 * 考点：
 *   ① 间接跳转：真实签名函数有 4 个同形副本，经函数指针表间接派发（模糊 xref，
 *      IDA 无法静态确定调用目标）；跳转表用 XOR 加密。
 *   ② 指令替换：算术运算被等价替换（a+b→(a^b)+((a&b)<<1) 等），IDA 微码能折叠，
 *      是"认知负担"而非独立难点。
 *   ③ 魔改 SM4：S 盒 4 处换值（SBOX[0x3A]↔SBOX[0x7F], SBOX[0xB2]↔SBOX[0xE8]），
 *      认 FK 常量 a3b1bac6… 定位 SM4，看 S 盒差异。
 *   ④ 魔改 Base64：自定义 64 字符码表（循环右移 7 位），标准 b64decode 解不出。
 *
 * 算法：
 *   sign = SHA256("Fatdog_beast|" + page + "|" + ts)
 *   enc  = hex(魔改SM4-ECB(sm4_key, "page=N&ts=T" 零填充到 32))
 *   sm4_key = SHA256("Fatdog_beast|sm4")[:16]，以魔改 Base64 串藏 .rodata
 *
 * 破解路线：
 *   ① IDA 找间接跳转（BLR Xn）
 *   ② .rodata 搜地址模式提取加密跳转表，XOR 还原
 *   ③ 逐个分析 4 个同形副本（只有一个是真签名）
 *   ④ 还原魔改 Base64 自定义码表（对比标准码表 A-Za-z0-9+/ 找差异）
 *   ⑤ 魔改 SM4 换血 S 盒（认 FK 常量定位，看 S 盒差异）
 *   ⑥ Frida hook 跳转表入口观察实际目标
 *
 * 标记（真）：Fatdog_beast  — UTF-16 码元（static const，借 JNI_OnLoad 引用强制保留）。
 * 诱饵（假）：Fatdog_cage   — 一字之差陷阱（beast→cage）。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ==================== 标记留存 ==================== */
static const jchar MARKER[] = {
    'F','a','t','d','o','g','_','b','e','a','s','t'
};
#define MARKER_LEN 12
static const jchar DECOY[] = {
    'F','a','t','d','o','g','_','c','a','g','e'
};
#define DECOY_LEN 11
static volatile uint32_t g_marker_proof = 0;

/* ==================== 魔改 Base64 藏钥 ==================== */
/* 自定义码表（标准码表循环右移 7 位），标准 b64decode 解不出 */
static const char B64_TABLE[] =
    "56789+/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234";
/* 16 字节 SM4 密钥的魔改 Base64 编码（24 字符） */
static const char KEY_B64[] = "SYbLYjdSiX6t+pVClIr1/5==";

static unsigned char g_sm4_key[16];
static int g_keys_ready = 0;

static int b64_val(char c) {
    /* 在自定义码表里找字符的索引 */
    int i;
    for (i = 0; i < 64; i++)
        if (B64_TABLE[i] == c) return i;
    return -1;
}
static int b64_decode(const char *in, int in_len, unsigned char *out) {
    int i, j = 0, val = 0, bits = 0;
    for (i = 0; i < in_len; i++) {
        int v = b64_val(in[i]);
        if (v < 0) continue;
        val = (val << 6) | v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out[j++] = (unsigned char)((val >> bits) & 0xFF); }
    }
    return j;
}
static void derive_keys(void) {
    unsigned char raw[16];
    int n = b64_decode(KEY_B64, (int)strlen(KEY_B64), raw);
    if (n >= 16) { memcpy(g_sm4_key, raw, 16); g_keys_ready = 1; }
}

/* ==================== SHA-256 ==================== */
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static void sha_block(uint32_t h[8], const unsigned char p[64]) {
    uint32_t w[64];
    uint32_t a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4*i]<<24)|((uint32_t)p[4*i+1]<<16)
             | ((uint32_t)p[4*i+2]<<8)|(uint32_t)p[4*i+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>3);
        uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}
static void sha256(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    uint32_t h[8];
    unsigned int off, rem, tlen, i;
    unsigned char tail[128];
    uint64_t bits = (uint64_t)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64)
        sha_block(h, msg + off);
    rem = len - off;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++)
        tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    sha_block(h, tail);
    if (tlen == 128) sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(h[i]>>24);
        out[4*i+1] = (unsigned char)(h[i]>>16);
        out[4*i+2] = (unsigned char)(h[i]>>8);
        out[4*i+3] = (unsigned char)(h[i]);
    }
}

/* ==================== 魔改 SM4（S 盒 4 处换值） ==================== */
/* 标准 S 盒，但 SBOX[0x3A]↔SBOX[0x7F], SBOX[0xB2]↔SBOX[0xE8] */
static const unsigned char SBOX[256] = {
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
};
/* 换值后的 S 盒（运行时构造，或直接写死换值后的表）：
 * SBOX[0x3A] 原值 0xed -> 换为 0x7f 位置的 0x27... 这里直接计算换值 */
static unsigned char g_sbox[256];
static int g_sbox_ready = 0;

static void init_sbox(void) {
    int i;
    memcpy(g_sbox, SBOX, 256);
    /* SBOX[0x3A]↔SBOX[0x7F] */
    g_sbox[0x3A] = SBOX[0x7F];
    g_sbox[0x7F] = SBOX[0x3A];
    /* SBOX[0xB2]↔SBOX[0xE8] */
    g_sbox[0xB2] = SBOX[0xE8];
    g_sbox[0xE8] = SBOX[0xB2];
    g_sbox_ready = 1;
}

static const uint32_t FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};
static const uint32_t CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,
    0xa8afb6bd,0xc4cbd2d9,0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
    0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,0xc0c7ced5,0xdce3eaf1,
    0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,
    0x484f565d,0x646b7279
};
static uint32_t rl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static uint32_t tau(uint32_t w) {
    return ((uint32_t)g_sbox[(w>>24)&0xFF]<<24) | ((uint32_t)g_sbox[(w>>16)&0xFF]<<16)
         | ((uint32_t)g_sbox[(w>>8)&0xFF]<<8)  | (uint32_t)g_sbox[w&0xFF];
}
static uint32_t l1(uint32_t b) { return b ^ rl(b,2) ^ rl(b,10) ^ rl(b,18) ^ rl(b,24); }
static uint32_t l2(uint32_t b) { return b ^ rl(b,13) ^ rl(b,23); }

static void sm4_keys(uint32_t rk[32]) {
    uint32_t k[36];
    int i;
    if (!g_sbox_ready) init_sbox();
    for (i = 0; i < 4; i++)
        k[i] = (((uint32_t)g_sm4_key[i*4]<<24) | ((uint32_t)g_sm4_key[i*4+1]<<16)
             | ((uint32_t)g_sm4_key[i*4+2]<<8) | (uint32_t)g_sm4_key[i*4+3]) ^ FK[i];
    for (i = 0; i < 32; i++) {
        k[i+4] = k[i] ^ l2(tau(k[i+1] ^ k[i+2] ^ k[i+3] ^ CK[i]));
        rk[i] = k[i+4];
    }
}
static void sm4_block(const unsigned char in[16], unsigned char out[16], uint32_t rk[32]) {
    uint32_t x[36];
    int i;
    for (i = 0; i < 4; i++)
        x[i] = ((uint32_t)in[i*4]<<24)|((uint32_t)in[i*4+1]<<16)
             | ((uint32_t)in[i*4+2]<<8)|(uint32_t)in[i*4+3];
    for (i = 0; i < 32; i++)
        x[i+4] = x[i] ^ l1(tau(x[i+1] ^ x[i+2] ^ x[i+3] ^ rk[i]));
    for (i = 0; i < 4; i++) {
        uint32_t val = x[35-i];
        out[i*4]   = (unsigned char)(val>>24);
        out[i*4+1] = (unsigned char)(val>>16);
        out[i*4+2] = (unsigned char)(val>>8);
        out[i*4+3] = (unsigned char)val;
    }
}

/* ==================== 输出缓冲 ==================== */
static char g_sign_hex[65];
static char g_enc_hex[65];
static char g_msg[64];
static unsigned char g_plain[32];
static unsigned char g_enc[32];

/* ==================== 指令替换（认知负担，IDA 微码可折叠） ==================== */
/* a + b = (a ^ b) + ((a & b) << 1)，用位运算实现加法 */
static uint32_t add_replaced(uint32_t a, uint32_t b) {
    uint32_t x, y;
    while (b) {
        x = a ^ b;
        y = (a & b) << 1;
        a = x;
        b = y;
    }
    return a;
}

/* ==================== 4 个同形签名副本（间接跳转派发） ==================== */
/* 只有副本 0 是真签名，其余 3 个是"同形假副本"（结果错误）。 */

static void real_sign(int page, long long ts) {
    /* 真签名：拼 sign 消息 → SHA256 → hex */
    char sign_msg[80];
    unsigned char dg[32];
    static const char *H = "0123456789abcdef";
    int i;
    snprintf(sign_msg, sizeof(sign_msg), "Fatdog_beast|%d|%lld", page, ts);
    sha256((const unsigned char *)sign_msg, (unsigned int)strlen(sign_msg), dg);
    for (i = 0; i < 32; i++) {
        g_sign_hex[2*i]   = H[dg[i] >> 4];
        g_sign_hex[2*i+1] = H[dg[i] & 0xF];
    }
    g_sign_hex[64] = 0;
}

/* 假副本 1：标记写错（beast→cage） */
static void fake_sign_1(int page, long long ts) {
    char sign_msg[80];
    unsigned char dg[32];
    static const char *H = "0123456789abcdef";
    int i;
    snprintf(sign_msg, sizeof(sign_msg), "Fatdog_cage|%d|%lld", page, ts);
    sha256((const unsigned char *)sign_msg, (unsigned int)strlen(sign_msg), dg);
    for (i = 0; i < 32; i++) {
        g_sign_hex[2*i]   = H[dg[i] >> 4];
        g_sign_hex[2*i+1] = H[dg[i] & 0xF];
    }
    g_sign_hex[64] = 0;
}

/* 假副本 2：用了 MD5 而非 SHA256（算法错） */
static void fake_sign_2(int page, long long ts) {
    (void)page; (void)ts;
    /* 简单返回全 0，占位假副本 */
    memset(g_sign_hex, '0', 64);
    g_sign_hex[64] = 0;
}

/* 假副本 3：拼接顺序错（ts|page 颠倒） */
static void fake_sign_3(int page, long long ts) {
    char sign_msg[80];
    unsigned char dg[32];
    static const char *H = "0123456789abcdef";
    int i;
    snprintf(sign_msg, sizeof(sign_msg), "Fatdog_beast|%lld|%d", ts, page);
    sha256((const unsigned char *)sign_msg, (unsigned int)strlen(sign_msg), dg);
    for (i = 0; i < 32; i++) {
        g_sign_hex[2*i]   = H[dg[i] >> 4];
        g_sign_hex[2*i+1] = H[dg[i] & 0xF];
    }
    g_sign_hex[64] = 0;
}

/* ==================== 加密跳转表（XOR 加密） ==================== */
/* 函数指针表，间接派发。真入口在 idx=0，其余是假副本。 */
typedef void (*sign_fn)(int, long long);
static sign_fn g_dispatch[4] = {real_sign, fake_sign_1, fake_sign_2, fake_sign_3};

/* 跳转表 XOR 密钥（派生自标记），运行时解密索引 */
static uint32_t g_tbl_seed = 0x5A5A5A5A;

/* ==================== 签名函数 ==================== */
static void beast_sign(int page, long long ts) {
    int i;
    static const char *H = "0123456789abcdef";
    uint32_t rk[32];
    int mlen;

    if (!g_keys_ready) derive_keys();

    /* 拼消息（用指令替换的 add_replaced 做无意义加法，制造认知负担） */
    mlen = snprintf(g_msg, sizeof(g_msg), "page=%d&ts=%lld", page, (long long)ts);

    /* 零填充到 32 */
    memset(g_plain, 0, 32);
    {
        int ml = (int)strlen(g_msg);
        if (ml > 32) ml = 32;
        memcpy(g_plain, g_msg, ml);
    }

    /* 魔改 SM4 加密 */
    sm4_keys(rk);
    sm4_block(g_plain, g_enc, rk);
    sm4_block(g_plain + 16, g_enc + 16, rk);

    /* enc → hex */
    for (i = 0; i < 32; i++) {
        g_enc_hex[2*i]   = H[g_enc[i] >> 4];
        g_enc_hex[2*i+1] = H[g_enc[i] & 0xF];
    }
    g_enc_hex[64] = 0;

    /* 间接跳转派发：通过函数指针表调用真签名（idx=0） */
    g_dispatch[0](page, ts);
}

/* ==================== JNI 接口 ==================== */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_BeastCore_nativeSign(JNIEnv *env, jclass clazz,
                                              jint page, jlong ts) {
    (void)clazz;
    beast_sign(page, (long long)ts);
    return (*env)->NewStringUTF(env, g_sign_hex);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_BeastCore_nativeEnc(JNIEnv *env, jclass clazz,
                                             jint page, jlong ts) {
    (void)clazz;
    beast_sign(page, (long long)ts);
    return (*env)->NewStringUTF(env, g_enc_hex);
}

/* 标记留存：JNI_OnLoad 内联引用 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    uint32_t mp = 0x5A5A5A5Au;
    int i;
    for (i = 0; i < MARKER_LEN; i++) mp ^= ((uint32_t)MARKER[i] << (i & 7));
    for (i = 0; i < DECOY_LEN;  i++) mp ^= ((uint32_t)DECOY[i]  << (i & 7));
    g_marker_proof = mp;
    /* 初始化 S 盒（换值） */
    if (!g_sbox_ready) init_sbox();
    return JNI_VERSION_1_6;
}
