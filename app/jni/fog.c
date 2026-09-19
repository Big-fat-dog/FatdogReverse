/*
 * 天地秘境·迷阵 KL51：迷雾初开——控制流平坦化基础。
 *
 * 考点：OLLVM 的「控制流平坦化」(Control Flow Flattening)。
 * 核心签名函数被改写成 switch-case dispatcher（主分发器 + 状态变量），
 * 16 个 case 里 10 个真实、6 个虚假（提前 return 0 / 死循环 / 无意义运算）。
 * 玩家需：①找主分发器 ②画状态流转图 ③标真假 case ④还原真实计算链。
 *
 * 算法（迷阵五关里唯一用 HMAC 的一关）：
 *   enc  = hex(AES-128-ECB(aes_key, "page=N&ts=T" 零填充))
 *   sign = HMAC-SHA256(mac_key, enc)
 *   aes_key = SHA256("Fatdog_haze|aes")[:16]
 *   mac_key = SHA256("Fatdog_haze|mac")[:32]
 *   密钥以 Base64 串藏 .rodata（b64decode 即得，Base64 不是加密）。
 *
 * 破解路线：
 *   ① IDA 找 switch dispatcher（LDR R0,[Rn] + CMP + BHI）
 *   ② D810 default_unflattening_ollvm.json 一键去平坦化
 *   ③ 或 angr 符号执行恢复块间跳转
 *   ④ 手工画状态流转图、标真假 case
 *   ⑤ Python 复刻 AES+HMAC 取数
 *   ⑥ Frida hook dispatcher 观察状态流转
 *
 * 标记（真）：Fatdog_haze  — UTF-16 码元（static const，借 JNI_OnLoad 引用强制保留）。
 * 诱饵（假）：Fatdog_hazey — 一字之差陷阱（haze→hazey）。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ==================== 标记留存 ==================== */
static const jchar MARKER[] = {
    'F','a','t','d','o','g','_','h','a','z','e'
};
#define MARKER_LEN 11
static const jchar DECOY[] = {
    'F','a','t','d','o','g','_','h','a','z','e','y'
};
#define DECOY_LEN 12
static volatile uint32_t g_marker_proof = 0;

/* ==================== Base64 藏钥 ==================== */
/* 48 字节 = aes_key(16) + mac_key(32)，运行时 b64decode 即得 */
static const char KEY_B64[] =
    "Ta3Cl3qmIAKoSuT/fOLZdeh9zWfdc4OdmyGpOCfWrNAQmtDZqKD+4peWYPutolUL";

static unsigned char g_aes_key[16];
static unsigned char g_mac_key[32];
static int g_keys_ready = 0;

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
        if (bits >= 8) {
            bits -= 8;
            out[j++] = (unsigned char)((val >> bits) & 0xFF);
        }
    }
    return j;
}

static void derive_keys(void) {
    unsigned char raw[48];
    int n = b64_decode(KEY_B64, (int)strlen(KEY_B64), raw);
    if (n >= 48) {
        memcpy(g_aes_key, raw, 16);
        memcpy(g_mac_key, raw + 16, 32);
        g_keys_ready = 1;
    }
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

/* ==================== HMAC-SHA256 ==================== */
static void hmac_sha256(const unsigned char *key, unsigned int klen,
                        const unsigned char *msg, unsigned int mlen,
                        unsigned char out[32]) {
    unsigned char k_pad[64], k_hash[32], o_key[64], i_key[64];
    unsigned char inner[32], outer[128];
    int i;
    if (klen > 64) { sha256(key, klen, k_hash); key = k_hash; klen = 32; }
    memset(k_pad, 0, 64);
    memcpy(k_pad, key, klen);
    for (i = 0; i < 64; i++) { i_key[i] = k_pad[i] ^ 0x36; o_key[i] = k_pad[i] ^ 0x5C; }
    memcpy(outer, i_key, 64);
    memcpy(outer + 64, msg, mlen);
    sha256(outer, 64 + mlen, inner);
    memcpy(outer, o_key, 64);
    memcpy(outer + 64, inner, 32);
    sha256(outer, 64 + 32, out);
}

/* ==================== AES-128-ECB（加密，标准 S 盒） ==================== */
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

static unsigned char g_rk[176]; /* 11 rounds × 16 bytes */

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

static void aes_sub(unsigned char s[16]) {
    int i; for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
}
static void aes_shift(unsigned char s[16]) {
    unsigned char t;
    t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
    t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
    t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
}
static unsigned char xtime(unsigned char x) {
    return (unsigned char)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}
static void aes_mix(unsigned char s[16]) {
    int c;
    for (c = 0; c < 4; c++) {
        int i = c * 4;
        unsigned char a0=s[i], a1=s[i+1], a2=s[i+2], a3=s[i+3];
        unsigned char x = a0 ^ a1 ^ a2 ^ a3;
        s[i]   ^= x ^ xtime(a0^a1);
        s[i+1] ^= x ^ xtime(a1^a2);
        s[i+2] ^= x ^ xtime(a2^a3);
        s[i+3] ^= x ^ xtime(a3^a0);
    }
}
static void aes_addkey(unsigned char s[16], int round) {
    int i; for (i = 0; i < 16; i++) s[i] ^= g_rk[round*16+i];
}

static void aes128_enc_block(unsigned char out[16], const unsigned char in[16]) {
    unsigned char s[16];
    int round;
    memcpy(s, in, 16);
    aes_addkey(s, 0);
    for (round = 1; round < 10; round++) {
        aes_sub(s); aes_shift(s); aes_mix(s); aes_addkey(s, round);
    }
    aes_sub(s); aes_shift(s); aes_addkey(s, 10);
    memcpy(out, s, 16);
}

static void aes128_ecb_enc(const unsigned char key[16],
                           const unsigned char *plain, unsigned int len,
                           unsigned char *cipher) {
    unsigned int i;
    aes128_expand(key);
    for (i = 0; i < len; i += 16)
        aes128_enc_block(cipher + i, plain + i);
}

/* ==================== 控制流平坦化核心 ==================== */
/*
 * flat_derive_and_sign：被"平坦化"的签名函数。
 * 原本顺序执行的逻辑（拼消息 → AES 加密 → hex → HMAC 签名 → hex）
 * 被改写为 switch-case 主分发器：状态变量 state 决定下一个真实块。
 * 16 个 case：10 真实（0~9）+ 6 虚假（10~15）。
 * 虚假 case：10 提前 return、11 死循环、12 无意义运算、
 *           13 复制 case 0 但改坏状态、14 空跳、15 返回全 0。
 */
static char g_sign_hex[65];
static char g_enc_hex[65];
static char g_msg[64];
static unsigned char g_plain[32];
static unsigned char g_enc[32];
static unsigned char g_dg[32];

static void flat_derive_and_sign(int page, long long ts) {
    int state = 0;
    int i;

    if (!g_keys_ready) derive_keys();

    for (;;) {
        switch (state) {
        /* ---- 真实块 ---- */
        case 0: /* 拼消息 */
            snprintf(g_msg, sizeof(g_msg), "page=%d&ts=%lld", page, ts);
            state = 1; break;
        case 1: /* 拼明文（零填充到 32 = 2 个 AES 块） */
            memset(g_plain, 0, 32);
            {
                int ml = (int)strlen(g_msg);
                if (ml > 32) ml = 32;
                memcpy(g_plain, g_msg, ml);
            }
            state = 2; break;
        case 2: /* AES-128-ECB 加密（2 块） */
            aes128_ecb_enc(g_aes_key, g_plain, 32, g_enc);
            state = 3; break;
        case 3: /* enc → hex */
            {
                static const char *H = "0123456789abcdef";
                for (i = 0; i < 32; i++) {
                    g_enc_hex[2*i]   = H[g_enc[i] >> 4];
                    g_enc_hex[2*i+1] = H[g_enc[i] & 0xF];
                }
                g_enc_hex[64] = 0;
            }
            state = 4; break;
        case 4: /* HMAC-SHA256(mac_key, enc_hex) */
            hmac_sha256(g_mac_key, 32, (const unsigned char *)g_enc_hex, 64, g_dg);
            state = 5; break;
        case 5: /* sign → hex */
            {
                static const char *H = "0123456789abcdef";
                for (i = 0; i < 32; i++) {
                    g_sign_hex[2*i]   = H[g_dg[i] >> 4];
                    g_sign_hex[2*i+1] = H[g_dg[i] & 0xF];
                }
                g_sign_hex[64] = 0;
            }
            state = 9; break;
        case 6: /* 冗余块：无用运算（凑真实块数量，让图更复杂） */
            {
                volatile int t = 0;
                t = t + 1; t = t * 2; t = t ^ 0x5A;
            }
            state = 7; break;
        case 7: /* 冗余块：再无用运算 */
            state = 8; break;
        case 8: /* 冗余块：跳回 */
            state = 5; break;
        case 9: /* 出口 */
            return;

        /* ---- 虚假块 ---- */
        case 10: /* 提前 return（截断） */
            g_sign_hex[0] = 0;
            return;
        case 11: /* 死循环 */
            for (;;) { /* hang */ }
        case 12: /* 无意义运算后继续 */
            {
                volatile int t = 12345;
                t = t * 9876;
            }
            state = 0; break;
        case 13: /* 复制 case 0 但改坏状态（跳向死循环） */
            snprintf(g_msg, sizeof(g_msg), "page=%d&ts=%lld", page, ts);
            state = 11; break;
        case 14: /* 空跳 */
            state = 1; break;
        case 15: /* 返回全 0 */
            memset(g_sign_hex, '0', 64);
            g_sign_hex[64] = 0;
            return;
        default:
            state = 0; break;
        }
    }
}

/* ==================== JNI 接口 ==================== */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FogCore_nativeFlatSign(JNIEnv *env, jclass clazz,
                                                jint page, jlong ts) {
    (void)clazz;
    flat_derive_and_sign(page, (long long)ts);
    return (*env)->NewStringUTF(env, g_sign_hex);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FogCore_nativeEnc(JNIEnv *env, jclass clazz,
                                           jint page, jlong ts) {
    (void)clazz;
    flat_derive_and_sign(page, (long long)ts);
    return (*env)->NewStringUTF(env, g_enc_hex);
}

/* 标记留存：JNI_OnLoad 内联引用，防 --gc-sections 删除真标记 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    uint32_t mp = 0x5A5A5A5Au;
    int i;
    for (i = 0; i < MARKER_LEN; i++) mp ^= ((uint32_t)MARKER[i] << (i & 7));
    for (i = 0; i < DECOY_LEN;  i++) mp ^= ((uint32_t)DECOY[i]  << (i & 7));
    g_marker_proof = mp;
    return JNI_VERSION_1_6;
}
