/*
 * 天地秘境·迷阵 KL53：移形换位——字符串加密（String Encryption）。
 *
 * 考点：OLLVM 的「字符串加密」(String Encryption)。
 * 关键字符串（标记 / AES 钥 / IV）不落盘明文，而是以 XOR 字节块存放，
 * 运行时（constructor / init_array / JNI_OnLoad）才解密写回内存。
 * 三变体对应 OLLVM 商业混淆（Armariris/Hikari）的三代字符串加密：
 *   ① 古典 datadiv_decode：导出特征函数，constructor 里解密；
 *   ② 隐藏名：解密函数名混淆，仍在 .init_array 执行；
 *   ③ 运行时：解密推迟到 JNI_OnLoad，密钥来自其它数据。
 *
 * 算法（迷阵第三关，MD5 签名）：
 *   sign = MD5("Fatdog_shift|" + page + "|" + ts)
 *   enc  = hex(AES-128-CBC(aes_key, IV, "page=N&ts=T" PKCS5))
 *   aes_key = SHA256("Fatdog_shift|aes")[:16]，IV = SHA256("Fatdog_shift|iv")[:16]
 *   标记 + 密钥 Base64 串均经 XOR 字符串加密，strings 看不到明文。
 *
 * 破解路线：
 *   ① strings/导出表找 datadiv_decode 特征 → hook 拿解密后明文
 *   ② unicorn/AndroidNativeEmu 模拟执行 .init_array 段，dump 解密后的 .data
 *   ③ Frida 在 JNI_OnLoad 后 dump 内存明文
 *
 * 标记（真）：Fatdog_shift  — 经字符串加密（XOR 0x5A），运行时解密。
 * 诱饵（假）：Fatdog_swap    — 一字之差陷阱（shift→swap）。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ==================== 字符串加密：标记 Fatdog_shift（XOR 0x5A） ==================== */
/* 变体一：古典 datadiv_decode。密文字节块，constructor 解密写回。 */
static unsigned char g_mark_enc[12] = {
    28, 59, 46, 62, 53, 61, 5, 41, 50, 51, 60, 46
};
#define MARK_LEN 12
static unsigned char g_mark[12];
static int g_mark_ready = 0;
static volatile uint32_t g_marker_proof = 0;

/* ==================== 字符串加密：AES 钥 Base64（XOR 0x3C） ==================== */
/* 变体二：隐藏名解密函数（std__string___4921590060622252445 风格），init_array 执行。 */
static unsigned char g_aes_b64_enc[24] = {
    118, 9, 81, 82, 125, 69, 106, 68, 112, 126, 83, 101,
    82, 119, 80, 78, 125, 88, 76, 102, 125, 75, 1, 1
};
#define AES_B64_LEN 24
static char g_aes_b64[25];
static int g_aes_ready = 0;

/* ==================== 字符串加密：IV Base64（XOR 0x69） ==================== */
/* 变体三：JNI_OnLoad 运行时解密。 */
static unsigned char g_iv_b64_enc[24] = {
    24, 80, 4, 95, 32, 26, 8, 10, 94, 57, 24, 40,
    8, 12, 34, 38, 80, 25, 66, 56, 4, 14, 84, 84
};
#define IV_B64_LEN 24
static char g_iv_b64[25];
static int g_iv_ready = 0;

/* ==================== Base64 解码 ==================== */
static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
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

/* ==================== 密钥 ==================== */
static unsigned char g_aes_key[16];
static unsigned char g_iv[16];

/* ==================== 变体二：隐藏名解密函数 ==================== */
/* 名字刻意混淆成 C++ mangling 风格，但仍是 init_array 段执行的普通 C 函数。 */
static void std__string___4921590060622252445(void) {
    int i;
    for (i = 0; i < AES_B64_LEN; i++)
        g_aes_b64[i] = (char)(g_aes_b64_enc[i] ^ 0x3C);
    g_aes_b64[AES_B64_LEN] = '\0';
    g_aes_ready = 1;
}

/* 变体一：datadiv_decode 特征函数，constructor 里执行（进 .init_array） */
static void datadiv_decode1234567890(void) {
    int i;
    for (i = 0; i < MARK_LEN; i++)
        g_mark[i] = g_mark_enc[i] ^ 0x5A;
    g_mark_ready = 1;
    /* 顺带解 AES 钥（变体二的函数名是"隐藏"的，这里两个都触发） */
    std__string___4921590060622252445();
}

/* constructor：进 .init_array 段（OLLVM 字符串解密的经典藏身处） */
__attribute__((constructor)) static void _init_strings(void) {
    datadiv_decode1234567890();
}

/* 变体三：JNI_OnLoad 运行时解密 IV */
static void decrypt_iv_runtime(void) {
    int i;
    for (i = 0; i < IV_B64_LEN; i++)
        g_iv_b64[i] = (char)(g_iv_b64_enc[i] ^ 0x69);
    g_iv_b64[IV_B64_LEN] = '\0';
    g_iv_ready = 1;
}

static void derive_keys(void) {
    if (!g_mark_ready) datadiv_decode1234567890();
    if (!g_aes_ready) std__string___4921590060622252445();
    if (!g_iv_ready) decrypt_iv_runtime();
    b64_decode(g_aes_b64, AES_B64_LEN, g_aes_key);
    b64_decode(g_iv_b64, IV_B64_LEN, g_iv);
}

/* ==================== MD5 ==================== */
static uint32_t md5_rotl(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

static void md5_transform(uint32_t state[4], const unsigned char block[64]) {
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
    static const int S[64] = {
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5,9,14,20, 5,9,14,20, 5,9,14,20, 5,9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
    };
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t M[16];
    int i;
    for (i = 0; i < 16; i++)
        M[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1]<<8)
             | ((uint32_t)block[i*4+2]<<16) | ((uint32_t)block[i*4+3]<<24);
    for (i = 0; i < 64; i++) {
        uint32_t F;
        int g;
        if (i < 16) { F = (b & c) | ((~b) & d); g = i; }
        else if (i < 32) { F = (d & b) | ((~d) & c); g = (5*i + 1) % 16; }
        else if (i < 48) { F = b ^ c ^ d; g = (3*i + 5) % 16; }
        else { F = c ^ (b | (~d)); g = (7*i) % 16; }
        F = F + a + K[i] + M[g];
        a = d; d = c; c = b;
        b = b + md5_rotl(F, S[i]);
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static void md5(const unsigned char *msg, unsigned int len, unsigned char out[16]) {
    uint32_t state[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    unsigned char buf[128];
    unsigned int i, rem = len % 64;
    uint64_t bits = (uint64_t)len * 8ULL;
    for (i = 0; i < len / 64; i++)
        md5_transform(state, msg + i * 64);
    memset(buf, 0, sizeof(buf));
    memcpy(buf, msg + (len / 64) * 64, rem);
    buf[rem] = 0x80;
    if (rem >= 56) {
        md5_transform(state, buf);
        memset(buf, 0, 64);
    }
    for (i = 0; i < 8; i++)
        buf[56 + i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    md5_transform(state, buf);
    for (i = 0; i < 4; i++) {
        out[i*4]   = (unsigned char)(state[i] & 0xFF);
        out[i*4+1] = (unsigned char)((state[i] >> 8) & 0xFF);
        out[i*4+2] = (unsigned char)((state[i] >> 16) & 0xFF);
        out[i*4+3] = (unsigned char)((state[i] >> 24) & 0xFF);
    }
}

/* ==================== AES-128-CBC ==================== */
static const unsigned char SBOX[256] = {
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
static const unsigned char RCON[10] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};
static unsigned char g_rk[176];

static void aes128_expand(const unsigned char key[16]) {
    unsigned char temp[4];
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++) g_rk[i*4+j] = key[i*4+j];
    for (i = 4; i < 44; i++) {
        temp[0] = g_rk[(i-1)*4+0];
        temp[1] = g_rk[(i-1)*4+1];
        temp[2] = g_rk[(i-1)*4+2];
        temp[3] = g_rk[(i-1)*4+3];
        if (i % 4 == 0) {
            unsigned char t = temp[0];
            temp[0] = SBOX[temp[1]] ^ RCON[i/4-1];
            temp[1] = SBOX[temp[2]];
            temp[2] = SBOX[temp[3]];
            temp[3] = SBOX[t];
        }
        for (j = 0; j < 4; j++)
            g_rk[i*4+j] = g_rk[(i-4)*4+j] ^ temp[j];
    }
}
static void aes_sub(unsigned char s[16]) { int i; for(i=0;i<16;i++) s[i]=SBOX[s[i]]; }
static void aes_shift(unsigned char s[16]) {
    unsigned char t;
    t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
    t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
    t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
}
static unsigned char xtime(unsigned char x) { return (unsigned char)((x<<1)^(((x>>7)&1)*0x1b)); }
static void aes_mix(unsigned char s[16]) {
    int c;
    for (c = 0; c < 4; c++) {
        int i = c*4;
        unsigned char a0=s[i],a1=s[i+1],a2=s[i+2],a3=s[i+3];
        unsigned char x = a0^a1^a2^a3;
        s[i]^=x^xtime(a0^a1); s[i+1]^=x^xtime(a1^a2);
        s[i+2]^=x^xtime(a2^a3); s[i+3]^=x^xtime(a3^a0);
    }
}
static void aes_addkey(unsigned char s[16], int round) {
    int i; for(i=0;i<16;i++) s[i]^=g_rk[round*16+i];
}
static void aes128_enc_block(unsigned char out[16], const unsigned char in[16]) {
    unsigned char s[16]; int round;
    memcpy(s, in, 16);
    aes_addkey(s, 0);
    for (round = 1; round < 10; round++) { aes_sub(s); aes_shift(s); aes_mix(s); aes_addkey(s, round); }
    aes_sub(s); aes_shift(s); aes_addkey(s, 10);
    memcpy(out, s, 16);
}

/* AES-128-CBC 加密（PKCS5 填充） */
static void aes128_cbc_enc(const unsigned char key[16], const unsigned char iv[16],
                           const unsigned char *plain, unsigned int len,
                           unsigned char *cipher) {
    unsigned char prev[16], block[16];
    unsigned int i, j, full;
    aes128_expand(key);
    memcpy(prev, iv, 16);
    full = len / 16 * 16;
    for (i = 0; i < full; i += 16) {
        for (j = 0; j < 16; j++) block[j] = plain[i+j] ^ prev[j];
        aes128_enc_block(cipher + i, block);
        memcpy(prev, cipher + i, 16);
    }
    /* PKCS5 填充最后一个块 */
    {
        unsigned char pad = 16 - (len - full);
        unsigned char last[16];
        for (j = full; j < len; j++) last[j - full] = plain[j];
        for (j = len - full; j < 16; j++) last[j] = pad;
        for (j = 0; j < 16; j++) block[j] = last[j] ^ prev[j];
        aes128_enc_block(cipher + full, block);
    }
}

/* ==================== 输出缓冲 ==================== */
static char g_sign_hex[33];
static char g_enc_hex[65];
static char g_msg[64];
static unsigned char g_enc[32];

/* ==================== 签名函数 ==================== */
static void shift_sign(int page, long long ts) {
    int i, mlen;
    static const char *H = "0123456789abcdef";
    unsigned char dg[16];
    char sign_msg[80];

    if (!g_mark_ready || !g_aes_ready || !g_iv_ready) derive_keys();

    /* enc = AES-128-CBC(aes_key, iv, "page=N&ts=T") */
    mlen = snprintf(g_msg, sizeof(g_msg), "page=%d&ts=%lld", page, (long long)ts);
    aes128_cbc_enc(g_aes_key, g_iv, (const unsigned char *)g_msg, (unsigned int)mlen, g_enc);
    /* 32 字节密文 → hex */
    for (i = 0; i < 32; i++) {
        g_enc_hex[2*i]   = H[g_enc[i] >> 4];
        g_enc_hex[2*i+1] = H[g_enc[i] & 0xF];
    }
    g_enc_hex[64] = 0;

    /* sign = MD5("Fatdog_shift|page|ts") */
    snprintf(sign_msg, sizeof(sign_msg), "Fatdog_shift|%d|%lld", page, (long long)ts);
    md5((const unsigned char *)sign_msg, (unsigned int)strlen(sign_msg), dg);
    for (i = 0; i < 16; i++) {
        g_sign_hex[2*i]   = H[dg[i] >> 4];
        g_sign_hex[2*i+1] = H[dg[i] & 0xF];
    }
    g_sign_hex[32] = 0;
}

/* ==================== JNI 接口 ==================== */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_StringGuard_nativeSign(JNIEnv *env, jclass clazz,
                                                jint page, jlong ts) {
    (void)clazz;
    shift_sign(page, (long long)ts);
    return (*env)->NewStringUTF(env, g_sign_hex);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_StringGuard_nativeEnc(JNIEnv *env, jclass clazz,
                                               jint page, jlong ts) {
    (void)clazz;
    shift_sign(page, (long long)ts);
    return (*env)->NewStringUTF(env, g_enc_hex);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    /* 变体三：运行时解密 IV（推迟到 JNI_OnLoad，而非 init_array） */
    if (!g_iv_ready) decrypt_iv_runtime();
    /* 标记留存：引用 g_mark 防止被 gc-sections 优化掉 */
    {
        uint32_t mp = 0x5A5A5A5Au;
        int i;
        for (i = 0; i < MARK_LEN; i++) mp ^= ((uint32_t)g_mark[i] << (i & 7));
        g_marker_proof = mp;
    }
    return JNI_VERSION_1_6;
}
