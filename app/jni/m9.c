/* libm9.so ——「幽冥合卷」（签名校验对抗 · L47，收官综合卷）
 * 三点互验记账（Application 记账 → Activity 核账 → native 再核账互锁）
 * + CRC 自校验基线（L33 手法回收）
 * + certHash 参与 AES 密钥派生（L46 手法回收）
 * + 响应体 AES-ECB 加密。
 * 任一环节缺失 → 静默投毒一字节（L32 手法回收）。
 *
 * 守卫矩阵：g_guard.audit == 1 && g_guard.tick == 0xABCD && g_guard.recheck == 1
 * CRC 自校验：启动时对 guard_fn 前 256 字节做 CRC32，与基准比对。
 *
 * 正解三条：①Frida spawn 抢跑伪造三点位；②patch so 废 CRC 校验+比较；
 * ③重打包 + 完整复刻派生链（最硬核）。
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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
    122,93,72,88,83,91,101,94,85,82,88,78
};
#define MARK_LEN 12

/* ==================== guard 矩阵 ==================== */
typedef struct {
    int audit;     /* Application.audit() 递增 */
    int tick;      /* Activity 传入固定值 0xABCD */
    int recheck;   /* native 再核账 = 1 */
} GuardState;

static GuardState g_guard = {0, 0, 0};
static int g_guard_activated = 0;

/* ==================== CRC 自校验 ==================== */
static unsigned int g_crc_baseline = 0;
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

/* CRC 覆盖区域：guard_check 函数前 256 字节（解法②：patch 此区域不影响 CRC 基准） */
extern void m9_guard_check(void);
static void m9_crc_init(void) {
    /* 用函数指针地址前 256 字节算 CRC */
    const unsigned char *fn = (const unsigned char *)((void *)m9_guard_check);
    g_crc_baseline = m9_crc32(fn, 256);
    g_crc_ready = 1;
}

static int m9_crc_verify(void) {
    const unsigned char *fn = (const unsigned char *)((void *)m9_guard_check);
    return m9_crc32(fn, 256) == g_crc_baseline;
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

/* ==================== 派生密钥 ==================== */
static unsigned char g_hmac_key[32];
static unsigned char g_aes_key[16];
static int g_keys_ready = 0;

static void m9_derive_keys(void) {
    unsigned char full[32];
    int i;
    if (!g_bench_ready) m9_unlock_bench();
    /* full = SHA256(certHash || "Fatdog_seal") */
    {
        unsigned char *buf = (unsigned char *)malloc(32 + MARK_LEN);
        if (!buf) return;
        memcpy(buf, g_bench, 32);
        for (i = 0; i < MARK_LEN; i++)
            buf[32 + i] = (unsigned char)(MARK_X[i] ^ 0x3C);
        m9_sha256(buf, 32 + MARK_LEN, full);
        free(buf);
    }
    memcpy(g_hmac_key, full, 32);
    memcpy(g_aes_key, full, 16);
    g_keys_ready = 1;
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
    t=state[3]; state[3]=state[7]; state[7]=state[11]; state[11]=state[15]; state[15]=t;
}

static unsigned char m9_xtime2(unsigned char x) {
    return (unsigned char)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static void m9_aes256_inv_mix(unsigned char state[16]) {
    int c;
    for (c = 0; c < 4; c++) {
        int i = c * 4;
        unsigned char a0=state[i], a1=state[i+1], a2=state[i+2], a3=state[i+3];
        state[i]   = (unsigned char)(m9_xtime2(m9_xtime2(a0^a2)) ^ m9_xtime2(a1^a3) ^ a0^a1^a2^a3);
        state[i+1] = (unsigned char)(m9_xtime2(m9_xtime2(a1^a3)) ^ m9_xtime2(a0^a2) ^ a0^a1^a2^a3);
        state[i+2] = (unsigned char)(m9_xtime2(m9_xtime2(a0^a2)) ^ m9_xtime2(a0^a1) ^ a0^a1^a2^a3);
        state[i+3] = (unsigned char)(m9_xtime2(m9_xtime2(a1^a3)) ^ m9_xtime2(a2^a3) ^ a0^a1^a2^a3);
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

static void m9_aes256_ecb_dec(const unsigned char key[32],
                              const unsigned char *cipher, unsigned int len,
                              unsigned char *plain) {
    unsigned int i;
    m9_aes256_expand(key);
    for (i = 0; i + 16 <= len; i += 16)
        m9_aes256_block_dec(plain + i, cipher + i);
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

/* ==================== guard_check（CRC 覆盖区域起点） ==================== */
void m9_guard_check(void) {
    volatile int dummy = 0;
    dummy++;
    dummy += g_bench_ready;
    dummy += g_keys_ready;
    dummy += g_crc_baseline;
}

/* ==================== 静默投毒 ==================== */
static void m9_poison(unsigned char *data, unsigned int len) {
    if (len > 0) data[0] ^= 0xFF;
}

/* ==================== 签名 + 加密复合操作 ==================== */

/* guard_seal: 验证 guard 矩阵 + CRC，通过才正常签名+加密 */
static int g_sealed = 0;

static void m9_guard_seal(void) {
    /* 三重检查 */
    if (g_guard.audit != 1 || g_guard.tick != 0xABCD || g_guard.recheck != 1) {
        g_sealed = 1; /* 标记：输出将被投毒 */
        return;
    }
    if (g_crc_ready && !m9_crc_verify()) {
        g_sealed = 1;
        return;
    }
    g_sealed = 0;
}

/* nativeSignEnc: HMAC-SHA256(g_hmac_key, "page=N&ts=T") → hex;
 * 同时 AES 加密 "page=N" 到 out_enc（调用方负责 hex 编码）。 */
static void m9_sign_and_enc(int page, long ts,
                            char sign_out[65], unsigned char enc_out[32]) {
    char msg[64];
    int mlen;
    unsigned char dg[32];
    static const char *H = "0123456789abcdef";
    int i;

    if (!g_keys_ready) m9_derive_keys();

    /* 签名 */
    mlen = snprintf(msg, sizeof(msg), "page=%d&ts=%lld", page, (long long)ts);
    m9_hmac_sha256(g_hmac_key, 32, (const unsigned char *)msg, (unsigned int)mlen, dg);
    for (i = 0; i < 32; i++) {
        sign_out[2*i]   = H[dg[i] >> 4];
        sign_out[2*i+1] = H[dg[i] & 0xF];
    }
    sign_out[64] = 0;

    /* 加密 "page=N" */
    {
        char plain[16];
        int plen = snprintf(plain, sizeof(plain), "page=%d", page);
        m9_aes256_ecb_enc(g_aes_key, (const unsigned char *)plain,
                          (unsigned int)plen, enc_out);
    }

    /* 投毒检查 */
    if (g_sealed) {
        m9_poison((unsigned char *)sign_out, 64);
        m9_poison(enc_out, 16);
    }
}

/* ==================== JNI 接口 ==================== */

#ifndef M9_HOST_TEST

/* audit: Application 启动时调用，递增审计计数 */
JNIEXPORT void JNICALL
Java_com_fatdog_reverse_Wp_nativeAudit(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    if (!g_bench_ready) m9_unlock_bench();
    if (!g_crc_ready) m9_crc_init();
    g_guard.audit++;
}

/* guard: Activity 核账，传入固定 tick 值 + recheck 值 */
JNIEXPORT jboolean JNICALL
Java_com_fatdog_reverse_Wp_nativeGuard(JNIEnv *env, jclass clazz,
                                        jint tick, jint recheck) {
    (void)env; (void)clazz;
    g_guard.tick = tick;
    g_guard.recheck = recheck;
    m9_guard_seal();
    return g_sealed ? JNI_FALSE : JNI_TRUE;
}

/* sign: HMAC-SHA256 签名，返回 hex string */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Wp_nativeSign(JNIEnv *env, jclass clazz,
                                       jint page, jlong ts) {
    char hex[65];
    (void)clazz;
    m9_sign_and_enc(page, ts, hex, (unsigned char[32]){0});
    return (*env)->NewStringUTF(env, hex);
}

/* signAndEnc: 签名 + 加密，返回 [sign_hex, enc_hex] */
JNIEXPORT jobjectArray JNICALL
Java_com_fatdog_reverse_Wp_nativeSignAndEnc(JNIEnv *env, jclass clazz,
                                             jint page, jlong ts) {
    char sign_hex[65];
    unsigned char enc_raw[16];
    char enc_hex[33];
    static const char *H = "0123456789abcdef";
    jobjectArray result;
    int i;
    (void)clazz;

    m9_sign_and_enc(page, ts, sign_hex, enc_raw);

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

/* decryptResp: AES-ECB 解密 hex 密文 → 明文字符串 */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Wp_nativeDecrypt(JNIEnv *env, jclass clazz,
                                          jstring hexCipher) {
    const char *hex;
    unsigned char *ct;
    unsigned char plain[128];
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

    if (!g_keys_ready) m9_derive_keys();
    m9_aes256_expand(g_aes_key);
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
    static const char *H = "0123456789abcdef";
    int i;

    printf("=== L47 幽冥合卷 · 本地自测 ===\n");

    m9_unlock_bench();
    m9_crc_init();
    printf("CRC baseline: 0x%08x\n", g_crc_baseline);
    printf("CRC verify: %s\n", m9_crc_verify() ? "PASS" : "FAIL");

    m9_derive_keys();
    printf("hmac_key: ");
    for (i = 0; i < 32; i++) printf("%02x", g_hmac_key[i]);
    printf("\naes_key: ");
    for (i = 0; i < 16; i++) printf("%02x", g_aes_key[i]);
    printf("\n");

    /* 正常签名 */
    g_guard.audit = 1; g_guard.tick = 0xABCD; g_guard.recheck = 1;
    m9_guard_seal();
    printf("guard: %s\n", g_sealed ? "SEALED (bad)" : "OK");

    m9_sign_and_enc(1, 1700000000L, sign_hex, enc_raw);
    printf("sign(page=1&ts=1700000000) = %s\n", sign_hex);
    printf("enc(page=1) = ");
    for (i = 0; i < 16; i++) printf("%02x", enc_raw[i]);
    printf("\n");

    /* 投毒测试 */
    g_guard.audit = 0;  /* 破坏 audit */
    m9_guard_seal();
    printf("guard (bad audit): %s\n", g_sealed ? "SEALED (poison)" : "OK");
    m9_sign_and_enc(1, 1700000000L, sign_hex, enc_raw);
    printf("poisoned sign[0..3]: %02x%02x%02x%02x\n",
           (unsigned char)sign_hex[0], (unsigned char)sign_hex[1],
           (unsigned char)sign_hex[2], (unsigned char)sign_hex[3]);

    return 0;
}

#endif /* M9_HOST_TEST */
