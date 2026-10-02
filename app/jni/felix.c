/* libfelix.so ——「幽冥合卷」（签名校验对抗 · L47，收官综合卷）
 * 三点互验记账（Activity 记账 → Activity 核账 → native 再核账互锁）
 * + CRC 自校验基线（覆盖三个基准数组的**烘焙常量**）
 * + 当前包 certHash 参与密钥派生（L46 手法回收）
 * + 响应体 AES-ECB 加密。
 * 任一环节不满足 → 派生落到诱饵标记 → 服务端回【脏数据】（不再报错）。
 *
 * 守卫矩阵：g_guard.audit == 1 && tick == 0xABCD && recheck == 1 && certOk == 1
 * CRC 自校验：CRC32(MARK_X ‖ DMARK_X ‖ BENCH_X) 与烘焙基准比对——
 *             把基准数组改成自己的证书摘要会被当场抓到。
 *
 * 2026-10-02 双层链路改造：
 *   ① g_door 纯开关常量：出厂 0x2E，改成 0x9B 才允许取数（逼出一次重打包重签）；
 *   ② nativeSeed(der) 把「当前包证书摘要」纳入守卫矩阵——原先 ② 只查"guard 函数有没有被调用"，
 *      重打包者原样保留调用即可通过，证书其实从未参与判定（派生用的是内置基准）；
 *   ③ nativeVerdictToken() 产出一次性令牌 vt，参与密钥派生：key = SHA256(基准 ‖ 标记 ‖ vt)。
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifndef M9_HOST_TEST
#include <jni.h>
#endif

/* ==================== certHash（^0x66 藏匿，非 static） ==================== */
unsigned char BENCH_X[32] = {
    0x5d,0xd4,0x75,0x2a,0xc5,0xd7,0x6d,0xca,
    0xb2,0x5f,0x03,0xb6,0xe5,0xe8,0x9c,0xf6,
    0x88,0x95,0x10,0x38,0x8b,0xee,0x54,0xf4,
    0xf7,0x0e,0xac,0x68,0x44,0x74,0x51,0x98,
};
static unsigned char g_bench[32];
static int g_bench_ready = 0;

static void m9_unlock_bench(void) {
    int i;
    for (i = 0; i < 32; i++) g_bench[i] = (unsigned char)(BENCH_X[i] ^ 0x66);
    g_bench_ready = 1;
}

/* ==================== marker: "Fatdog_seal" ^0x3C ==================== */
static const unsigned char MARK_X[] = {
    122,93,72,88,83,91,99,79,89,93,80
};
#define MARK_LEN 11

/* "Fatdog_steal" ^0x3C ——诱饵标记（与真标记一字之差；守卫不过时用它派生 → 服务端回脏数据） */
static const unsigned char DMARK_X[] = {
    122,93,72,88,83,91,99,79,72,89,93,80
};
#define DMARK_LEN 12

/* ---------- ① 第一层障碍：纯开关常量（非判定逻辑，刻意做轻） ----------
 * 出厂值 0x2E；门不开则 nativeSignAndEnc / nativeVerdictToken 返回空 → App 取不到数。
 * 把这一字节改成 0x9B（或把下面那条比较改掉）即可开门。 */
volatile unsigned int g_door = 0x2E;
#define M9_DOOR_OPEN 0x9B

static int m9_door_open(void) {
    return (g_door == (unsigned int)M9_DOOR_OPEN) ? 1 : 0;
}

/* ==================== guard 矩阵 ==================== */
typedef struct {
    int audit;     /* 启动记账：递增 */
    int tick;      /* Activity 传入固定值 0xABCD */
    int recheck;   /* native 再核账 = 1 */
    int cert_ok;   /* 当前包证书摘要 == 内置基准 */
} GuardState;

static GuardState g_guard = {0, 0, 0, 0};
static int g_checked = 0;

/* ==================== CRC 自校验（覆盖基准数组的烘焙常量） ==================== */
#define M9_CRC_BASELINE 0xCDDA9987u
static int g_crc_ready = 0;

static unsigned int m9_crc32(const unsigned char *data, unsigned int len) {
    unsigned int crc = 0xFFFFFFFF;
    unsigned int i, j;
    for (i = 0; i < len; i++) {
        crc ^= data[i];
        for (j = 0; j < 8; j++) {
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320;
            else crc >>= 1;
        }
    }
    return ~crc;
}

/* CRC 覆盖三个基准数组（MARK_X ‖ DMARK_X ‖ BENCH_X）。
 * 它们是编译期常量，因此基准值可烘焙：改动任一数组（最常见的攻击：把 BENCH_X
 * 换成自己证书的摘要，或把诱饵标记改成真标记）都会被当场抓到。 */
static unsigned int m9_arrays_crc(void) {
    unsigned char buf[MARK_LEN + DMARK_LEN + 32];
    int n = 0, i;
    for (i = 0; i < MARK_LEN; i++)  buf[n++] = MARK_X[i];
    for (i = 0; i < DMARK_LEN; i++) buf[n++] = DMARK_X[i];
    for (i = 0; i < 32; i++)        buf[n++] = BENCH_X[i];
    return m9_crc32(buf, (unsigned int)n);
}

static int m9_crc_verify(void) {
    return m9_arrays_crc() == (unsigned int)M9_CRC_BASELINE;
}


/* ==================== SHA-256 ==================== */
static const unsigned int K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static unsigned int m9_rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }

static void m9_sha_block(unsigned int h[8], const unsigned char p[64]) {
    unsigned int w[64];
    unsigned int a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[4*i]<<24)|((unsigned int)p[4*i+1]<<16)
             | ((unsigned int)p[4*i+2]<<8)|(unsigned int)p[4*i+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = m9_rotr(w[i-15],7) ^ m9_rotr(w[i-15],18) ^ (w[i-15]>>3);
        unsigned int s1 = m9_rotr(w[i-2],17) ^ m9_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = m9_rotr(e,6)^m9_rotr(e,11)^m9_rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = m9_rotr(a,2)^m9_rotr(a,13)^m9_rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

static void m9_sha256(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned int h[8];
    unsigned int off, rem, tlen, i;
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64)
        m9_sha_block(h, msg + off);
    rem = len - off;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++)
        tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    m9_sha_block(h, tail);
    if (tlen == 128) m9_sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(h[i]>>24);
        out[4*i+1] = (unsigned char)(h[i]>>16);
        out[4*i+2] = (unsigned char)(h[i]>>8);
        out[4*i+3] = (unsigned char)(h[i]);
    }
}

/* ==================== HMAC-SHA256 ==================== */
static void m9_hmac_sha256(const unsigned char *key, unsigned int klen,
                           const unsigned char *msg, unsigned int mlen,
                           unsigned char out[32]) {
    unsigned char k_pad[64], k_hash[32], o_key[64], i_key[64];
    unsigned char inner[32];
    unsigned char outer[128];
    int i;
    if (klen > 64) { m9_sha256(key, klen, k_hash); key = k_hash; klen = 32; }
    memset(k_pad, 0, 64);
    memcpy(k_pad, key, klen);
    for (i = 0; i < 64; i++) { i_key[i] = k_pad[i] ^ 0x36; o_key[i] = k_pad[i] ^ 0x5C; }
    memcpy(outer, i_key, 64);
    memcpy(outer + 64, msg, mlen);
    m9_sha256(outer, 64 + mlen, inner);
    memcpy(outer, o_key, 64);
    memcpy(outer + 64, inner, 32);
    m9_sha256(outer, 64 + 32, out);
}

/* ==================== 派生密钥 + ③ 一次性令牌 ==================== */

static unsigned int g_rng_state = 0;

static unsigned int m9_rng_next(void) {
    unsigned int x;
    if (g_rng_state == 0) {
        g_rng_state = (((unsigned int)time(NULL)) ^ 0x9E3779B9u) | 1u;
    }
    x = g_rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_state = x;
    return x;
}

/* 守卫矩阵 + CRC 全过才算"已封缄通过"；否则走诱饵标记 */
static int m9_sealed_ok(void) {
    if (!g_checked) return 0;         /* nativeSeed 还没跑 = 证书未校验 */
    if (!g_crc_ready) return 0;       /* 启动记账还没跑 */
    if (g_guard.audit != 1 || g_guard.tick != 0xABCD || g_guard.recheck != 1) return 0;
    if (!g_guard.cert_ok) return 0;
    if (!m9_crc_verify()) return 0;
    return 1;
}

/* key = SHA256(内置基准(32) ‖ 标记(11) ‖ vt(ascii ≤16))，hmac 与 aes 同一把。
 *   守卫全过 → 标记 "Fatdog_seal"  → 服务端认，给真数据
 *   任一不过 → 标记 "Fatdog_steal" → 服务端认作诱饵，回【脏数据】 */
static void m9_derive_keys(const char *vt, unsigned char out[32]) {
    unsigned char buf[64];          /* 32 + 12(最长标记) + 16(vt) = 60，留余量 */
    const unsigned char *m;
    int mklen, i, n = 0;
    if (!g_bench_ready) m9_unlock_bench();
    if (m9_sealed_ok()) { m = MARK_X;  mklen = MARK_LEN;  }
    else                { m = DMARK_X; mklen = DMARK_LEN; }
    memcpy(buf, g_bench, 32);
    n = 32;
    for (i = 0; i < mklen; i++)
        buf[n++] = (unsigned char)(m[i] ^ 0x3C);
    if (vt) {
        for (i = 0; vt[i] && i < 16; i++) buf[n++] = (unsigned char)vt[i];
    }
    m9_sha256(buf, (unsigned int)n, out);
}


/* ==================== AES-256-ECB（最小实现） ==================== */
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

static unsigned char g_aes_rk[240]; /* 15 rounds × 16 bytes */

static void m9_aes256_expand(const unsigned char key[32]) {
    unsigned char temp[4];
    int i, j;
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 4; j++) g_aes_rk[i*4+j] = key[i*4+j];
    }
    for (i = 8; i < 60; i++) {
        temp[0] = g_aes_rk[(i-1)*4+0];
        temp[1] = g_aes_rk[(i-1)*4+1];
        temp[2] = g_aes_rk[(i-1)*4+2];
        temp[3] = g_aes_rk[(i-1)*4+3];
        if (i % 8 == 0) {
            unsigned char t = temp[0];
            temp[0] = SBOX[temp[1]] ^ RCON[i/8-1];
            temp[1] = SBOX[temp[2]];
            temp[2] = SBOX[temp[3]];
            temp[3] = SBOX[t];
        } else if (i % 8 == 4) {
            temp[0] = SBOX[temp[0]];
            temp[1] = SBOX[temp[1]];
            temp[2] = SBOX[temp[2]];
            temp[3] = SBOX[temp[3]];
        }
        for (j = 0; j < 4; j++)
            g_aes_rk[i*4+j] = g_aes_rk[(i-8)*4+j] ^ temp[j];
    }
}

static unsigned char m9_xtime(unsigned char x) {
    return (unsigned char)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static void m9_aes256_sub(unsigned char state[16]) {
    int i;
    for (i = 0; i < 16; i++) state[i] = SBOX[state[i]];
}

static void m9_aes256_shift(unsigned char state[16]) {
    unsigned char t;
    t=state[1]; state[1]=state[5]; state[5]=state[9]; state[9]=state[13]; state[13]=t;
    t=state[2]; state[2]=state[10]; state[10]=t; t=state[6]; state[6]=state[14]; state[14]=t;
    t=state[15]; state[15]=state[11]; state[11]=state[7]; state[7]=state[3]; state[3]=t;
}

static void m9_aes256_mix(unsigned char state[16]) {
    int c;
    for (c = 0; c < 4; c++) {
        int i = c * 4;
        unsigned char a0=state[i], a1=state[i+1], a2=state[i+2], a3=state[i+3];
        unsigned char x = a0 ^ a1 ^ a2 ^ a3;
        state[i]   ^= x ^ m9_xtime(a0^a1);
        state[i+1] ^= x ^ m9_xtime(a1^a2);
        state[i+2] ^= x ^ m9_xtime(a2^a3);
        state[i+3] ^= x ^ m9_xtime(a3^a0);
    }
}

static void m9_aes256_addkey(unsigned char state[16], int round) {
    int i;
    for (i = 0; i < 16; i++) state[i] ^= g_aes_rk[round*16+i];
}

static void m9_aes256_block(unsigned char out[16], const unsigned char in[16]) {
    unsigned char state[16];
    int round;
    memcpy(state, in, 16);
    m9_aes256_addkey(state, 0);
    for (round = 1; round < 14; round++) {
        m9_aes256_sub(state);
        m9_aes256_shift(state);
        m9_aes256_mix(state);
        m9_aes256_addkey(state, round);
    }
    m9_aes256_sub(state);
    m9_aes256_shift(state);
    m9_aes256_addkey(state, 14);
    memcpy(out, state, 16);
}

static void m9_aes256_ecb_enc(const unsigned char key[32],
                              const unsigned char *plain, unsigned int len,
                              unsigned char *cipher) {
    unsigned char block[16];
    unsigned int i, j, full;
    m9_aes256_expand(key);
    full = len / 16 * 16;
    for (i = 0; i < full; i += 16)
        m9_aes256_block(cipher + i, plain + i);
    /* PKCS7 padding */
    {
        unsigned char pad_val = 16 - (len - full);
        for (j = full; j < len; j++) block[j - full] = plain[j];
        for (j = len - full; j < 16; j++) block[j - full] = pad_val;
        m9_aes256_block(cipher + full, block);
    }
}

static void m9_aes256_inv_sub(unsigned char state[16]) {
    static const unsigned char INV_SBOX[256] = {
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
    int i;
    for (i = 0; i < 16; i++) state[i] = INV_SBOX[state[i]];
}

static void m9_aes256_inv_shift(unsigned char state[16]) {
    unsigned char t;
    t=state[13]; state[13]=state[9]; state[9]=state[5]; state[5]=state[1]; state[1]=t;
    t=state[2]; state[2]=state[10]; state[10]=t; t=state[6]; state[6]=state[14]; state[14]=t;
    /* 第 3 行：正向 ShiftRows 是左旋 3，InvShiftRows 必须是左旋 1（右旋 3）。
     * 原实现误把正向写法抄了过来 → 解密永远失败（2026-10-02 修正）。 */
    t=state[3]; state[3]=state[7]; state[7]=state[11]; state[11]=state[15]; state[15]=t;
}

/* GF(2^8) 乘法（AES 多项式 0x11B） */
static unsigned char m9_gmul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    int i;
    for (i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        {
            unsigned char hi = (unsigned char)(a & 0x80);
            a = (unsigned char)(a << 1);
            if (hi) a ^= 0x1b;
        }
        b = (unsigned char)(b >> 1);
    }
    return p;
}

/* 标准 InvMixColumns：每列乘以 [0e 0b 0d 09] 的循环矩阵。
 * 原实现是一组凭经验凑的 xtime 组合，与标准不符 → 解密结果全错（2026-10-02 修正）。 */
static void m9_aes256_inv_mix(unsigned char state[16]) {
    int c;
    for (c = 0; c < 4; c++) {
        int i = c * 4;
        unsigned char a0=state[i], a1=state[i+1], a2=state[i+2], a3=state[i+3];
        state[i]   = (unsigned char)(m9_gmul(a0,0x0e) ^ m9_gmul(a1,0x0b) ^ m9_gmul(a2,0x0d) ^ m9_gmul(a3,0x09));
        state[i+1] = (unsigned char)(m9_gmul(a0,0x09) ^ m9_gmul(a1,0x0e) ^ m9_gmul(a2,0x0b) ^ m9_gmul(a3,0x0d));
        state[i+2] = (unsigned char)(m9_gmul(a0,0x0d) ^ m9_gmul(a1,0x09) ^ m9_gmul(a2,0x0e) ^ m9_gmul(a3,0x0b));
        state[i+3] = (unsigned char)(m9_gmul(a0,0x0b) ^ m9_gmul(a1,0x0d) ^ m9_gmul(a2,0x09) ^ m9_gmul(a3,0x0e));
    }
}

static void m9_aes256_block_dec(unsigned char out[16], const unsigned char in[16]) {
    unsigned char state[16];
    int round;
    memcpy(state, in, 16);
    m9_aes256_addkey(state, 14);
    for (round = 13; round >= 1; round--) {
        m9_aes256_inv_shift(state);
        m9_aes256_inv_sub(state);
        m9_aes256_addkey(state, round);
        m9_aes256_inv_mix(state);
    }
    m9_aes256_inv_shift(state);
    m9_aes256_inv_sub(state);
    m9_aes256_addkey(state, 0);
    memcpy(out, state, 16);
}

static unsigned int m9_pkcs7_unpad(const unsigned char *data, unsigned int len) {
    if (len == 0 || len % 16 != 0) return 0;
    unsigned char pad_val = data[len - 1];
    if (pad_val == 0 || pad_val > 16) return 0;
    unsigned int i;
    for (i = len - pad_val; i < len; i++)
        if (data[i] != pad_val) return 0;
    return len - pad_val;
}

/* ==================== 签名 + 加密复合操作 ==================== */

/* nativeSignEnc: HMAC-SHA256(key, "page=N&ts=T") → hex;
 * 同时 AES 加密 "page=N" 到 out_enc（调用方负责 hex 编码）。
 * key 由 m9_sealed_ok() 的结论挑标记后派生——守卫不过则走诱饵标记，
 * 服务端据此回【脏数据】，而不是让本地输出报废（静默投毒改为静默喂假数据）。 */
static void m9_sign_and_enc(int page, long ts, const char *vt,
                            char sign_out[65], unsigned char enc_out[16]) {
    char msg[64];
    int mlen;
    unsigned char key[32];
    unsigned char dg[32];
    static const char *H = "0123456789abcdef";
    int i;

    m9_derive_keys(vt, key);

    /* 签名 */
    mlen = snprintf(msg, sizeof(msg), "page=%d&ts=%lld", page, (long long)ts);
    m9_hmac_sha256(key, 32, (const unsigned char *)msg, (unsigned int)mlen, dg);
    for (i = 0; i < 32; i++) {
        sign_out[2*i]   = H[dg[i] >> 4];
        sign_out[2*i+1] = H[dg[i] & 0xF];
    }
    sign_out[64] = 0;

    /* 加密 "page=N"（与 hmac 同一把 key 派生） */
    {
        char plain[16];
        int plen = snprintf(plain, sizeof(plain), "page=%d", page);
        m9_aes256_ecb_enc(key, (const unsigned char *)plain,
                          (unsigned int)plen, enc_out);
    }
}

/* ==================== JNI 接口 ==================== */

#ifndef M9_HOST_TEST

/* audit: 启动记账，递增审计计数（并确认 CRC 检查已就绪） */
JNIEXPORT void JNICALL
Java_com_fatdog_reverse_Wp_nativeAudit(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    if (!g_bench_ready) m9_unlock_bench();
    g_crc_ready = 1;
    g_guard.audit++;
}

/* seed: 递入当前包的证书 DER —— native 内摘要并与内置基准比对，纳入守卫矩阵 */
JNIEXPORT void JNICALL
Java_com_fatdog_reverse_Wp_nativeSeed(JNIEnv *env, jclass clazz, jbyteArray der) {
    unsigned char dg[32];
    (void)clazz;
    if (!g_bench_ready) m9_unlock_bench();
    g_checked = 1;
    g_guard.cert_ok = 0;
    if (der) {
        jsize len = (*env)->GetArrayLength(env, der);
        jbyte *p = (*env)->GetByteArrayElements(env, der, NULL);
        if (p) {
            m9_sha256((const unsigned char *)p, (unsigned int)len, dg);
            (*env)->ReleaseByteArrayElements(env, der, p, JNI_ABORT);
            g_guard.cert_ok = (memcmp(dg, g_bench, 32) == 0) ? 1 : 0;
        }
    }
}

/* guard: Activity 核账，传入固定 tick 值 + recheck 值；返回守卫矩阵结论 */
JNIEXPORT jboolean JNICALL
Java_com_fatdog_reverse_Wp_nativeGuard(JNIEnv *env, jclass clazz,
                                        jint tick, jint recheck) {
    (void)env; (void)clazz;
    g_guard.tick = tick;
    g_guard.recheck = recheck;
    return m9_sealed_ok() ? JNI_TRUE : JNI_FALSE;
}

/* ③ 取数令牌：门未开 → 空串（Java 侧据此不发包，即"取不到数"）；门已开 → 16 位 hex */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Wp_nativeVerdictToken(JNIEnv *env, jclass clazz) {
    static const char H[] = "0123456789abcdef";
    char out[17];
    unsigned int a, b;
    int i;
    (void)clazz;
    if (!m9_door_open()) return (*env)->NewStringUTF(env, "");
    a = m9_rng_next();
    b = m9_rng_next() ^ (((unsigned int)g_guard.audit) * 0x9E3779B9u);
    for (i = 0; i < 8; i++) out[i]     = H[(a >> (4 * i)) & 0xF];
    for (i = 0; i < 8; i++) out[8 + i] = H[(b >> (4 * i)) & 0xF];
    out[16] = 0;
    return (*env)->NewStringUTF(env, out);
}

/* sign: HMAC-SHA256 签名，返回 hex string；① 门未开 → 空串 */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Wp_nativeSign(JNIEnv *env, jclass clazz,
                                       jint page, jlong ts, jstring vt) {
    char hex[65];
    const char *v = NULL;
    (void)clazz;
    if (!m9_door_open()) return (*env)->NewStringUTF(env, "");
    if (vt) v = (*env)->GetStringUTFChars(env, vt, NULL);
    m9_sign_and_enc(page, ts, v, hex, (unsigned char[16]){0});
    if (v) (*env)->ReleaseStringUTFChars(env, vt, v);
    return (*env)->NewStringUTF(env, hex);
}

/* signAndEnc: 签名 + 加密，返回 [sign_hex, enc_hex]；① 门未开 → 返回空数组 */
JNIEXPORT jobjectArray JNICALL
Java_com_fatdog_reverse_Wp_nativeSignAndEnc(JNIEnv *env, jclass clazz,
                                             jint page, jlong ts, jstring vt) {
    char sign_hex[65];
    unsigned char enc_raw[16];
    char enc_hex[33];
    static const char *H = "0123456789abcdef";
    jobjectArray result;
    const char *v = NULL;
    int i;
    (void)clazz;

    if (!m9_door_open()) {
        return (*env)->NewObjectArray(env, 0,
                    (*env)->FindClass(env, "java/lang/String"), NULL);
    }

    if (vt) v = (*env)->GetStringUTFChars(env, vt, NULL);
    m9_sign_and_enc(page, ts, v, sign_hex, enc_raw);
    if (v) (*env)->ReleaseStringUTFChars(env, vt, v);

    for (i = 0; i < 16; i++) {
        enc_hex[2*i]   = H[enc_raw[i] >> 4];
        enc_hex[2*i+1] = H[enc_raw[i] & 0xF];
    }
    enc_hex[32] = 0;

    result = (*env)->NewObjectArray(env, 2,
                (*env)->FindClass(env, "java/lang/String"), NULL);
    (*env)->SetObjectArrayElement(env, result, 0,
                (*env)->NewStringUTF(env, sign_hex));
    (*env)->SetObjectArrayElement(env, result, 1,
                (*env)->NewStringUTF(env, enc_hex));
    return result;
}

/* decryptResp: AES-ECB 解密 hex 密文 → 明文字符串。
 * 必须带上该次请求用的 vt，才能复算出同一把 key。 */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Wp_nativeDecrypt(JNIEnv *env, jclass clazz,
                                          jstring hexCipher, jstring vt) {
    const char *hex;
    const char *v = NULL;
    unsigned char *ct;
    unsigned char plain[128];
    unsigned char key[32];
    unsigned int ct_len, pt_len;
    int i;
    (void)clazz;

    if (!hexCipher) return NULL;
    hex = (*env)->GetStringUTFChars(env, hexCipher, NULL);
    if (!hex) return NULL;

    ct_len = (unsigned int)strlen(hex) / 2;
    if (ct_len == 0 || ct_len > 128 || ct_len % 16 != 0) {
        (*env)->ReleaseStringUTFChars(env, hexCipher, hex);
        return NULL;
    }

    ct = (unsigned char *)malloc(ct_len);
    for (i = 0; i < (int)ct_len; i++) {
        unsigned int b;
        sscanf(hex + 2*i, "%02x", &b);
        ct[i] = (unsigned char)b;
    }
    (*env)->ReleaseStringUTFChars(env, hexCipher, hex);

    if (vt) v = (*env)->GetStringUTFChars(env, vt, NULL);
    m9_derive_keys(v, key);
    if (v) (*env)->ReleaseStringUTFChars(env, vt, v);

    m9_aes256_expand(key);
    for (i = 0; i + 16 <= (int)ct_len; i += 16)
        m9_aes256_block_dec(plain + i, ct + i);
    free(ct);

    pt_len = m9_pkcs7_unpad(plain, ct_len);
    if (pt_len == 0) return NULL;

    jstring result = (*env)->NewStringUTF(env, (const char *)plain);
    return result;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;(void)reserved;
    return JNI_VERSION_1_6;
}

#else /* M9_HOST_TEST */

int main(void) {
    char sign_hex[65];
    unsigned char enc_raw[16];
    unsigned char key[32];
    const char *VT = "0123456789abcdef";
    static const char *H = "0123456789abcdef";
    int i;

    printf("=== L47 幽冥合卷 · 本地自测 ===\n");

    m9_unlock_bench();
    printf("CRC actual : 0x%08x  (烘焙基准 0x%08x) -> %s\n",
           m9_arrays_crc(), (unsigned int)M9_CRC_BASELINE,
           m9_crc_verify() ? "PASS" : "FAIL");

    printf("door_open(default) = %d (expect 0)\n", m9_door_open());
    g_door = M9_DOOR_OPEN;
    printf("door_open(patched) = %d (expect 1)\n", m9_door_open());

    /* 守卫全过 → 真标记派生 */
    g_crc_ready = 1; g_checked = 1;
    g_guard.audit = 1; g_guard.tick = 0xABCD; g_guard.recheck = 1; g_guard.cert_ok = 1;
    printf("sealed_ok(real) = %d (expect 1)\n", m9_sealed_ok());
    m9_derive_keys(VT, key);
    printf("real  key = ");
    for (i = 0; i < 32; i++) printf("%02x", key[i]);
    printf("\n");

    m9_sign_and_enc(1, 1700000000L, VT, sign_hex, enc_raw);
    printf("sign(page=1&ts=1700000000) = %s\n", sign_hex);
    printf("enc(page=1) = ");
    for (i = 0; i < 16; i++) printf("%02x", enc_raw[i]);
    printf("\n");

    /* AES 往返 + PKCS7 去填充（服务端响应用同一条路径解密，这里验证一致性） */
    {
        unsigned char pt[16];
        unsigned int dl;
        m9_aes256_expand(key);
        m9_aes256_block_dec(pt, enc_raw);
        dl = m9_pkcs7_unpad(pt, 16);
        if (dl > 0 && dl < 16) pt[dl] = 0;
        printf("dec(page=1) = %s (len=%u, expect 6)\n", dl ? (char *)pt : "<fail>", dl);
    }

    /* 破坏 cert_ok → 诱饵标记派生（不再是投毒） */
    g_guard.cert_ok = 0;
    printf("sealed_ok(bad cert) = %d (expect 0)\n", m9_sealed_ok());
    m9_derive_keys(VT, key);
    printf("decoy key = ");
    for (i = 0; i < 32; i++) printf("%02x", key[i]);
    printf("\n");

    /* 破坏 CRC 基准（模拟把 BENCH_X 改成自己的证书摘要）→ 同样走诱饵 */
    g_guard.cert_ok = 1;
    BENCH_X[0] ^= 0x01;
    printf("sealed_ok(bad crc) = %d (expect 0)\n", m9_sealed_ok());
    BENCH_X[0] ^= 0x01;
    printf("sealed_ok(restored) = %d (expect 1)\n", m9_sealed_ok());

    g_guard.tick = 0x1234;
    printf("sealed_ok(bad tick) = %d (expect 0)\n", m9_sealed_ok());

    printf("vt a = %08x  vt b = %08x  (expect differ)\n", m9_rng_next(), m9_rng_next());
    (void)H;
    return 0;
}

#endif /* M9_HOST_TEST */
