/* libm1.so ——「冰封之钥」（由 gen_kl6.py 生成，勿手改）
 * 手写 AES-128：S 盒与压缩结构均为标准——认骨架足够；
 * 但轮常量 Rcon 有三处被换过血：
 *   idx3: 0x08 -> 0x9e   idx6: 0x40 -> 0x77   idx9: 0x36 -> 0xd4
 * 因此标准 AES 实现解不开本关密文。
 *
 * 密钥全部运行时派生：
 *   aes_key = sha256(<标记>|"aes") 前 16 字节
 *   mac     = sha256(<标记>|"mac") 全 32 字节
 * 真标记存成 UTF-16 码元数组（非 const 全局），默认 strings 不显示；
 * 另有一个明文诱饵标记与一段假密文等着粗心的猎物。
 */
#include <string.h>
#include <stdio.h>

#ifndef M1_HOST_TEST
#include <jni.h>
#endif

static const unsigned char SBOX[256] = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,
        0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
        0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,
        0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,
        0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
        0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,
        0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,
        0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
        0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,
        0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,
        0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
        0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,
        0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,
        0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
        0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,
        0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,
        0xb0,0x54,0xbb,0x16,
};

static const unsigned char RSBOX[256] = {
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,
        0x81,0xf3,0xd7,0xfb,0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,
        0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,0x54,0x7b,0x94,0x32,
        0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,
        0x6d,0x8b,0xd1,0x25,0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,
        0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,0x6c,0x70,0x48,0x50,
        0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,
        0xb8,0xb3,0x45,0x06,0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,
        0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,0x3a,0x91,0x11,0x41,
        0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,
        0x1c,0x75,0xdf,0x6e,0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,
        0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,0xfc,0x56,0x3e,0x4b,
        0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,
        0x27,0x80,0xec,0x5f,0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,
        0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,0xa0,0xe0,0x3b,0x4d,
        0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,
        0x55,0x21,0x0c,0x7d,
};

/* 换血后的轮常量（本关魔改点）：idx3/idx6/idx9 与标准不同 */
static const unsigned char RCON[10] = {0x01,0x02,0x04,0x9e,0x10,0x20,0x77,0x80,0x1b,0xd4};
/* 标准轮常量（仅供对照/噪声路径使用） */
static const unsigned char RCON_STD[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

/* 真标记 UTF-16 码元：非 static 非 const 全局，防止编译器常量折叠进指令流 */
unsigned short MARK[13] = {
        0x0046, 0x0061, 0x0074, 0x0064, 0x006f, 0x0067, 0x005f, 0x0070,
        0x0069, 0x0065, 0x0072, 0x0063, 0x0065,
};

/* 明文诱饵标记：非 static 保证落盘，strings 一眼可见，一字之差 */
const char DECOY_MARK[] = "Fatdog_piece";

/* 假密文：用诱饵标记派生的钥加密的一段“像样”假载荷 */
static const unsigned char DECOY_BLOB[32] = {
        0x91,0x61,0x60,0x74,0xcc,0x88,0xae,0xda,0x8f,0xdd,0xb7,0x61,
        0x99,0x06,0xf2,0x2d,0x76,0xdc,0x2a,0xc1,0x10,0xf5,0x35,0xcb,
        0xf1,0x22,0x0a,0x1d,0x2a,0xa1,0x49,0xeb,
};

/* ---------- SHA-256（任意长度） ---------- */

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

static unsigned int m1_rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }

static void m1_sha_block(unsigned int h[8], const unsigned char p[64]) {
    unsigned int w[64];
    unsigned int a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[4*i]<<24)|((unsigned int)p[4*i+1]<<16)
             | ((unsigned int)p[4*i+2]<<8)|(unsigned int)p[4*i+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = m1_rotr(w[i-15],7) ^ m1_rotr(w[i-15],18) ^ (w[i-15]>>3);
        unsigned int s1 = m1_rotr(w[i-2],17) ^ m1_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = m1_rotr(e,6)^m1_rotr(e,11)^m1_rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = m1_rotr(a,2)^m1_rotr(a,13)^m1_rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

static void m1_sha256(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned int h[8];
    unsigned int off;
    unsigned char tail[128];
    unsigned int rem, tlen, i;
    unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64)
        m1_sha_block(h, msg + off);
    rem = len - off;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++)
        tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    m1_sha_block(h, tail);
    if (tlen == 128) m1_sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(h[i]>>24);
        out[4*i+1] = (unsigned char)(h[i]>>16);
        out[4*i+2] = (unsigned char)(h[i]>>8);
        out[4*i+3] = (unsigned char)(h[i]);
    }
}

/* HMAC-SHA256：消息不超过 96 字节（本关只签 64 字符 hex），栈上拼装即可 */
static void m1_hmac_sha256(const unsigned char *key, unsigned int klen,
                           const unsigned char *msg, unsigned int mlen,
                           unsigned char out[32]) {
    unsigned char k0[64], ipad[64], opad[64], ih[32], buf[192];
    unsigned int i;
    memset(k0, 0, sizeof(k0));
    if (klen > 64) m1_sha256(key, klen, k0);
    else memcpy(k0, key, klen);
    for (i = 0; i < 64; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    if (mlen > 120) mlen = 120;
    memcpy(buf, ipad, 64);
    memcpy(buf + 64, msg, mlen);
    m1_sha256(buf, 64 + mlen, ih);
    memcpy(buf, opad, 64);
    memcpy(buf + 64, ih, 32);
    m1_sha256(buf, 96, out);
}

/* ---------- 魔改 AES-128 核心 ---------- */

static void m1_ark(unsigned char s[16], const unsigned char k[16]) {
    int i; for (i = 0; i < 16; i++) s[i] ^= k[i];
}

static void m1_key_expand(const unsigned char *key, const unsigned char *tab,
                          unsigned char rk[11][16]) {
    int i, j;
    unsigned char t[4];
    memcpy(rk[0], key, 16);
    for (i = 1; i <= 10; i++) {
        const unsigned char *p = rk[i-1];
        unsigned char *c = rk[i];
        t[0] = SBOX[p[13]] ^ tab[i-1];
        t[1] = SBOX[p[14]];
        t[2] = SBOX[p[15]];
        t[3] = SBOX[p[12]];
        for (j = 0; j < 4; j++) c[j] = p[j] ^ t[j];
        for (j = 4; j < 16; j++) c[j] = p[j] ^ c[j-4];
    }
}

static unsigned char m1_xt(unsigned char a) {
    return (unsigned char)((a & 0x80) ? ((a << 1) ^ 0x1B) : (a << 1));
}

static unsigned char m1_gmul(unsigned char a, unsigned char b) {
    unsigned char r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = m1_xt(a);
        b >>= 1;
    }
    return r;
}

static void m1_mix(unsigned char s[16]) {
    int c;
    for (c = 0; c < 4; c++) {
        unsigned char a0=s[4*c],a1=s[4*c+1],a2=s[4*c+2],a3=s[4*c+3];
        s[4*c+0] = m1_gmul(a0,2)^m1_gmul(a1,3)^a2^a3;
        s[4*c+1] = a0^m1_gmul(a1,2)^m1_gmul(a2,3)^a3;
        s[4*c+2] = a0^a1^m1_gmul(a2,2)^m1_gmul(a3,3);
        s[4*c+3] = m1_gmul(a0,3)^a1^a2^m1_gmul(a3,2);
    }
}

static void m1_inv_mix(unsigned char s[16]) {
    int c;
    for (c = 0; c < 4; c++) {
        unsigned char a0=s[4*c],a1=s[4*c+1],a2=s[4*c+2],a3=s[4*c+3];
        s[4*c+0] = m1_gmul(a0,14)^m1_gmul(a1,11)^m1_gmul(a2,13)^m1_gmul(a3,9);
        s[4*c+1] = m1_gmul(a0,9)^m1_gmul(a1,14)^m1_gmul(a2,11)^m1_gmul(a3,13);
        s[4*c+2] = m1_gmul(a0,13)^m1_gmul(a1,9)^m1_gmul(a2,14)^m1_gmul(a3,11);
        s[4*c+3] = m1_gmul(a0,11)^m1_gmul(a1,13)^m1_gmul(a2,9)^m1_gmul(a3,14);
    }
}

static void m1_shift(unsigned char s[16]) {
    unsigned char t;
    t = s[1];  s[1] = s[5];  s[5] = s[9];  s[9] = s[13]; s[13] = t;
    t = s[2];  s[2] = s[10]; s[10] = t;
    t = s[6];  s[6] = s[14]; s[14] = t;
    t = s[3];  s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t;
}

static void m1_inv_shift(unsigned char s[16]) {
    unsigned char t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2];  s[2] = s[10]; s[10] = t;
    t = s[6];  s[6] = s[14]; s[14] = t;
    t = s[3];  s[3] = s[7];  s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

static void m1_enc_block(const unsigned char *in, unsigned char *out,
                         unsigned char rk[11][16]) {
    unsigned char s[16];
    int r, i;
    memcpy(s, in, 16);
    m1_ark(s, rk[0]);
    for (r = 1; r <= 9; r++) {
        for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
        m1_shift(s);
        m1_mix(s);
        m1_ark(s, rk[r]);
    }
    for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    m1_shift(s);
    m1_ark(s, rk[10]);
    memcpy(out, s, 16);
}

static void m1_dec_block(const unsigned char *in, unsigned char *out,
                         unsigned char rk[11][16]) {
    unsigned char s[16];
    int r, i;
    memcpy(s, in, 16);
    m1_ark(s, rk[10]);
    for (r = 9; r >= 1; r--) {
        m1_inv_shift(s);
        for (i = 0; i < 16; i++) s[i] = RSBOX[s[i]];
        m1_ark(s, rk[r]);
        m1_inv_mix(s);
    }
    m1_inv_shift(s);
    for (i = 0; i < 16; i++) s[i] = RSBOX[s[i]];
    m1_ark(s, rk[0]);
    memcpy(out, s, 16);
}

/* 标记运行时拼装 + 派生：suffix 形如 "|aes"/"|mac" */
static void m1_derive(const char *suffix, unsigned char *out, int outlen) {
    char mk[32];
    char msg[48];
    unsigned char dg[32];
    int i, n = sizeof(MARK) / sizeof(unsigned short);
    int slen = (int)strlen(suffix);
    for (i = 0; i < n; i++) mk[i] = (char)(MARK[i] & 0xFF);
    mk[n] = 0;
    memcpy(msg, mk, (size_t)n);
    memcpy(msg + n, suffix, (size_t)slen);
    m1_sha256((const unsigned char *)msg, (unsigned int)(n + slen), dg);
    memcpy(out, dg, (size_t)outlen);
}

/* ---------- hex 工具 ---------- */

static void m1_hex_encode(const unsigned char *d, int n, char *out) {
    static const char *HEX = "0123456789abcdef";
    int i;
    for (i = 0; i < n; i++) {
        out[2*i]   = HEX[d[i] >> 4];
        out[2*i+1] = HEX[d[i] & 0xF];
    }
    out[2*n] = 0;
}

/* ---------- 业务核心（App 与玩家对拍的是同一套实现） ---------- */

static void m1_core_enc(int page, long long ts, char hex[65]) {
    char payload[32];
    unsigned char pt[32], ct[32], key[16], rk[11][16];
    int n, i;
    n = snprintf(payload, sizeof(payload), "page=%d&ts=%lld", page, ts);
    if (n < 0) n = 0;
    if (n > 31) n = 31;
    memset(pt, 0, sizeof(pt));
    for (i = 0; i < n; i++) pt[i] = (unsigned char)payload[i];
    m1_derive("|aes", key, 16);
    m1_key_expand(key, RCON, rk);
    for (i = 0; i + 16 <= 32; i += 16)
        m1_enc_block(pt + i, ct + i, rk);
    m1_hex_encode(ct, 32, hex);
}

static void m1_core_sign(const char *enc, char hex[65]) {
    unsigned char mk[32], dg[32];
    size_t elen = strlen(enc);
    if (elen > 120) elen = 120;
    m1_derive("|mac", mk, 32);
    m1_hmac_sha256(mk, 32, (const unsigned char *)enc, (unsigned int)elen, dg);
    m1_hex_encode(dg, 32, hex);
}

/* ---------- 导出面 ---------- */

/* 诱饵密文：拿去配真算法会解出一段“像样”的假载荷，别当真 */
const char *m1_decoy_seal(void) {
    static char hex[65];
    m1_hex_encode(DECOY_BLOB, 32, hex);
    return hex;
}

/* 噪声导出：无人调用，纯占位混淆 */
static volatile unsigned int m1_sink;

int m1_fold(unsigned int x) {
    unsigned int v = x;
    int i;
    for (i = 0; i < 4; i++) v = (v ^ (v << 3)) + 0x9E3779B9U;
    m1_sink = v;
    return (int)(v & 0xFFFF);
}

unsigned int m1_spin(unsigned int x, int n) {
    unsigned int v = (n & 31) ? ((x << (n & 31)) | (x >> (32 - (n & 31)))) : x;
    m1_sink = v ^ m1_sink;
    return v;
}

#ifndef M1_HOST_TEST

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Tj_nativeEnc(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char hex[65];
    (void)clazz;
    m1_core_enc((int)page, (long long)ts, hex);
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Tj_nativeSign(JNIEnv *env, jclass clazz, jstring enc) {
    char hex[65];
    const char *e;
    (void)clazz;
    if (!enc) return (*env)->NewStringUTF(env, "ERR_INPUT");
    e = (*env)->GetStringUTFChars(env, enc, NULL);
    if (!e) return (*env)->NewStringUTF(env, "ERR_UTF");
    m1_core_sign(e, hex);
    (*env)->ReleaseStringUTFChars(env, enc, e);
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;(void)reserved;
    return JNI_VERSION_1_6;
}

#endif /* !M1_HOST_TEST */

#ifdef M1_HOST_TEST
/* 主机自测：cc -DM1_HOST_TEST -o m1test m1.c && ./m1test */
int main(void) {
    char enc[65], sign[65];
    unsigned char key[16], rk[11][16], back[33];
    int i, j;
    m1_core_enc(1, 1787013761LL, enc);
    m1_core_sign(enc, sign);
    printf("sample_enc  = %s\n", enc);
    printf("sample_sign = %s\n", sign);
    /* 回环：用同一把钥匙解开自己的密文 */
    m1_derive("|aes", key, 16);
    m1_key_expand(key, RCON, rk);
    for (i = 0; i < 32; i += 16) {
        unsigned char ct[16];
        for (j = 0; j < 16; j++) {
            char c1 = enc[2*(i+j)], c2 = enc[2*(i+j)+1];
            int hi = (c1<='9')?(c1-'0'):(c1-'a'+10);
            int lo = (c2<='9')?(c2-'0'):(c2-'a'+10);
            ct[j] = (unsigned char)((hi<<4)|lo);
        }
        m1_dec_block(ct, back + i, rk);
    }
    back[32] = 0;
    printf("roundtrip   = %s\n", back);
    return 0;
}
#endif
