/*
 * 太玄之初 KKL5：诛仙台——VMP 虚拟机 + AES-128-CBC + 三点记账（教学版）。
 *
 * 对标商业壳（360/阿里/腾讯）的 onCreate 抽取：Java 侧不实现关键逻辑，
 * onCreate 只调用 nativeOnCreate()，真正的门禁判断在 VM 字节码里解释执行。
 * 参考：360 加固把 Activity.onCreate 抽成 native，由解释器逐条解密执行
 * （CSDN 104017413 / 简书 d057b3fa3cbc）。
 *
 * 链路：
 *  ① nativeOnCreate  : 先跑 VMP 程序（从真标记派生子钥）→ 校验 onCreate 指纹
 *  ② nativeUnseal    : 用 VM 派生的 AES 密钥解密 assets/kkl5 里的业务 DEX
 *  ③ nativeSign      : 每页取数前 AES-128-CBC 加密 page/ts 并 HMAC 签名
 *  ④ nativeCommit    : Java 收到一页后回调核账，闭合三点记账
 *
 * VMP 字节码由 tools/gen_kkl5_vm_program.py 生成，滚动 XOR 加密放在
 * kkl5_vm_program.h；真标记只作为 VM 立即数存在，诱饵 Fatdog_ascent
 * 派生出的签名会被服务端 403。
 */
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

#include "kkl5_vm_program.h"

/* 真标记：UTF-16 藏匿（仅静态取证参考；运行时派生完全走 VM 字节码） */
static const volatile jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F, 0x0061, 0x0073, 0x0063, 0x0065, 0x006E, 0x0064
};
#define MARKER_LEN (sizeof(MARKER) / sizeof(jchar))
static const char DECOY[] = "Fatdog_ascent";

/* ================= SHA-256 / HMAC ================= */
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
#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (RR(x,2)^RR(x,13)^RR(x,22))
#define EP1(x) (RR(x,6)^RR(x,11)^RR(x,25))
#define S0(x) (RR(x,7)^RR(x,18)^((x)>>3))
#define S1(x) (RR(x,17)^RR(x,19)^((x)>>10))

static void sha256(const uint8_t *m, size_t l, uint8_t o[32]) {
    uint32_t h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a;
    uint32_t h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    size_t n = l + 1;
    size_t rem = n % 64;
    size_t pad = rem > 56 ? 120 - rem : 56 - rem;
    n += pad + 8;
    std::vector<uint8_t> buf(n, 0);
    memcpy(buf.data(), m, l);
    buf[l] = 0x80;
    uint64_t bits = (uint64_t)l * 8;
    for (int i = 0; i < 8; i++) buf[n - 1 - i] = (uint8_t)(bits >> (i * 8));
    for (size_t off = 0; off < n; off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)buf[off + i*4] << 24) | ((uint32_t)buf[off + i*4+1] << 16)
                 | ((uint32_t)buf[off + i*4+2] << 8) |  (uint32_t)buf[off + i*4+3];
        }
        for (int i = 16; i < 64; i++) w[i] = S1(w[i-2]) + w[i-7] + S0(w[i-15]) + w[i-16];
        uint32_t a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,hh=h7;
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + EP1(e) + CH(e,f,g) + K256[i] + w[i];
            uint32_t t2 = EP0(a) + MAJ(a,b,c);
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h0+=a; h1+=b; h2+=c; h3+=d; h4+=e; h5+=f; h6+=g; h7+=hh;
    }
    uint32_t hs[8] = {h0,h1,h2,h3,h4,h5,h6,h7};
    for (int i = 0; i < 8; i++) {
        o[i*4]   = (uint8_t)(hs[i] >> 24);
        o[i*4+1] = (uint8_t)(hs[i] >> 16);
        o[i*4+2] = (uint8_t)(hs[i] >> 8);
        o[i*4+3] = (uint8_t)hs[i];
    }
}

static void hmac_sha256(const uint8_t *key, size_t klen,
                        const uint8_t *msg, size_t mlen, uint8_t out[32]) {
    uint8_t k0[64] = {0};
    if (klen > 64) sha256(key, klen, k0); else memcpy(k0, key, klen);
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    std::vector<uint8_t> inner(64 + mlen);
    memcpy(inner.data(), ipad, 64);
    memcpy(inner.data() + 64, msg, mlen);
    uint8_t ih[32];
    sha256(inner.data(), inner.size(), ih);
    std::vector<uint8_t> outer(64 + 32);
    memcpy(outer.data(), opad, 64);
    memcpy(outer.data() + 64, ih, 32);
    sha256(outer.data(), outer.size(), out);
}

static void to_hex(const uint8_t *in, int n, char *out) {
    const char *t = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[i*2] = t[(in[i] >> 4) & 0xF];
        out[i*2+1] = t[in[i] & 0xF];
    }
    out[n*2] = '\0';
}

/* ================= AES-128-CBC + PKCS#7 ================= */
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
static const uint8_t RCON[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};

static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1B)); }
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

static void aes_expand(const uint8_t key[16], uint8_t rk[176]) {
    memcpy(rk, key, 16);
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        memcpy(t, rk + (i - 1) * 4, 4);
        if (i % 4 == 0) {
            uint8_t tmp = t[0];
            t[0] = (uint8_t)(SBOX[t[1]] ^ RCON[i / 4]);
            t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]];
            t[3] = SBOX[tmp];
        }
        for (int j = 0; j < 4; j++) rk[i * 4 + j] = (uint8_t)(rk[(i - 4) * 4 + j] ^ t[j]);
    }
}

static void aes_encrypt_block(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    memcpy(s, in, 16);
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
    for (int round = 1; round <= 10; round++) {
        uint8_t t[16];
        for (int i = 0; i < 16; i++) t[i] = SBOX[s[i]];
        uint8_t u[16];
        u[0]=t[0]; u[1]=t[5]; u[2]=t[10]; u[3]=t[15];
        u[4]=t[4]; u[5]=t[9]; u[6]=t[14]; u[7]=t[3];
        u[8]=t[8]; u[9]=t[13]; u[10]=t[2]; u[11]=t[7];
        u[12]=t[12]; u[13]=t[1]; u[14]=t[6]; u[15]=t[11];
        if (round != 10) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0=u[c*4], a1=u[c*4+1], a2=u[c*4+2], a3=u[c*4+3];
                uint8_t all = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
                t[c*4]   = (uint8_t)(a0 ^ all ^ xtime((uint8_t)(a0 ^ a1)));
                t[c*4+1] = (uint8_t)(a1 ^ all ^ xtime((uint8_t)(a1 ^ a2)));
                t[c*4+2] = (uint8_t)(a2 ^ all ^ xtime((uint8_t)(a2 ^ a3)));
                t[c*4+3] = (uint8_t)(a3 ^ all ^ xtime((uint8_t)(a3 ^ a0)));
            }
            memcpy(u, t, 16);
        }
        for (int i = 0; i < 16; i++) s[i] = (uint8_t)(u[i] ^ rk[round * 16 + i]);
    }
    memcpy(out, s, 16);
}

static void aes_decrypt_block(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    memcpy(s, in, 16);
    for (int i = 0; i < 16; i++) s[i] ^= rk[160 + i];
    for (int round = 9; round >= 0; round--) {
        uint8_t t[16];
        t[0]=s[0]; t[1]=s[13]; t[2]=s[10]; t[3]=s[7];
        t[4]=s[4]; t[5]=s[1]; t[6]=s[14]; t[7]=s[11];
        t[8]=s[8]; t[9]=s[5]; t[10]=s[2]; t[11]=s[15];
        t[12]=s[12]; t[13]=s[9]; t[14]=s[6]; t[15]=s[3];
        for (int i = 0; i < 16; i++) s[i] = INV_SBOX[t[i]];
        for (int i = 0; i < 16; i++) s[i] ^= rk[round * 16 + i];
        if (round != 0) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0=s[c*4], a1=s[c*4+1], a2=s[c*4+2], a3=s[c*4+3];
                t[c*4]   = (uint8_t)(gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9));
                t[c*4+1] = (uint8_t)(gmul(a0,9)  ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13));
                t[c*4+2] = (uint8_t)(gmul(a0,13) ^ gmul(a1,9)  ^ gmul(a2,14) ^ gmul(a3,11));
                t[c*4+3] = (uint8_t)(gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9)  ^ gmul(a3,14));
            }
            memcpy(s, t, 16);
        }
    }
    memcpy(out, s, 16);
}

static std::vector<uint8_t> aes_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16],
                                            const uint8_t *data, size_t len) {
    uint8_t rk[176];
    aes_expand(key, rk);
    size_t padlen = 16 - (len % 16);
    std::vector<uint8_t> out(16 + len + padlen);
    memcpy(out.data(), iv, 16);
    uint8_t prev[16];
    memcpy(prev, iv, 16);
    std::vector<uint8_t> plain(data, data + len);
    plain.insert(plain.end(), padlen, (uint8_t)padlen);
    for (size_t off = 0; off < plain.size(); off += 16) {
        uint8_t x[16], c[16];
        for (int i = 0; i < 16; i++) x[i] = (uint8_t)(plain[off + i] ^ prev[i]);
        aes_encrypt_block(rk, x, c);
        memcpy(out.data() + 16 + off, c, 16);
        memcpy(prev, c, 16);
    }
    return out;
}

static bool aes_cbc_decrypt(const uint8_t key[16], const uint8_t *data, size_t len,
                            std::vector<uint8_t> &out) {
    if (len < 32 || (len % 16) != 0) return false;
    uint8_t rk[176];
    aes_expand(key, rk);
    const uint8_t *iv = data;
    const uint8_t *ct = data + 16;
    size_t n = len - 16;
    out.resize(n);
    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < n; off += 16) {
        uint8_t d[16];
        aes_decrypt_block(rk, ct + off, d);
        for (int i = 0; i < 16; i++) out[off + i] = (uint8_t)(d[i] ^ prev[i]);
        memcpy(prev, ct + off, 16);
    }
    uint8_t padlen = out.back();
    if (padlen == 0 || padlen > 16 || padlen > out.size()) return false;
    for (size_t i = out.size() - padlen; i < out.size(); i++)
        if (out[i] != padlen) return false;
    out.resize(out.size() - padlen);
    return true;
}

/* ================= VMP 解释器 ================= */
enum {
    OP_MOV = 0x01, OP_ADDI = 0x02, OP_XOR = 0x03, OP_XORI = 0x04,
    OP_AND = 0x05, OP_OR = 0x06, OP_SHL = 0x07, OP_SHR = 0x08,
    OP_ROL = 0x09, OP_ROR = 0x0A, OP_CMP = 0x10, OP_JMP = 0x11,
    OP_JZ = 0x12, OP_JNZ = 0x13, OP_ADD = 0x14, OP_SUB = 0x15,
    OP_MUL = 0x16, OP_NOP = 0x17, OP_HALT = 0x18
};

struct VmResult {
    uint32_t regs[16];
    int steps;
    bool halted;
};

static bool kkl5_vm_run(const uint8_t *enc, size_t enc_len, VmResult &res) {
    size_t nwords = enc_len / 4;
    if (nwords == 0) return false;
    std::vector<uint32_t> words(nwords, 0);
    for (size_t i = 0; i < enc_len; i++) {
        uint8_t b = (uint8_t)(enc[i] ^ kKkl5VmRollingKey[i % KKL5_VM_KEY_LEN]);
        words[i / 4] |= ((uint32_t)b) << ((i % 4) * 8);
    }
    memset(res.regs, 0, sizeof(res.regs));
    res.steps = 0;
    res.halted = false;
    int pc = 0;
    while (pc >= 0 && (size_t)pc < nwords && res.steps < 500000) {
        uint32_t w = words[pc];
        uint32_t op = (w >> 24) & 0xFF;
        uint32_t imm = w & 0xFFFF;
        uint32_t rd = 0;
        uint32_t rs = 0;
        res.steps++;
        switch (op) {
        case OP_MOV:
            res.regs[rd] = (res.regs[rd] & 0xFFFFu) | (imm << 16);
            break;
        case OP_ADDI: res.regs[rd] += imm; break;
        case OP_XOR:  res.regs[rd] ^= res.regs[rs]; break;
        case OP_XORI: res.regs[rd] ^= imm; break;
        case OP_AND:  res.regs[rd] &= rs ? res.regs[rs] : imm; break;
        case OP_OR:   res.regs[rd] |= res.regs[rs]; break;
        case OP_SHL:  res.regs[rd] <<= imm; break;
        case OP_SHR:  res.regs[rd] >>= imm; break;
        case OP_ROL:  res.regs[rd] = ((res.regs[rd] << imm) | (res.regs[rd] >> (8 - imm))) & 0xFF; break;
        case OP_ROR:  res.regs[rd] = ((res.regs[rd] >> imm) | (res.regs[rd] << (8 - imm))) & 0xFF; break;
        case OP_CMP:  res.regs[0] = (res.regs[rd] == res.regs[rs]) ? 1 : 0; break;
        case OP_JMP:  pc += (int)imm; break;
        case OP_JZ:   if (res.regs[rd] == 0) pc += (int)imm; break;
        case OP_JNZ:  if (res.regs[rd] != 0) pc += (int)imm; break;
        case OP_ADD:  res.regs[rd] += res.regs[rs]; break;
        case OP_SUB:  res.regs[rd] -= res.regs[rs]; break;
        case OP_MUL:  res.regs[rd] *= imm; break;
        case OP_NOP:  break;
        case OP_HALT: res.halted = true; goto done;
        default: return false;
        }
        pc++;
    }
done:
    return res.halted;
}

static bool kkl5_vm_key(const uint8_t *enc, size_t enc_len, int base_reg,
                        uint8_t *out, int nbytes) {
    VmResult r;
    if (!kkl5_vm_run(enc, enc_len, r)) return false;
    if (r.steps < 100) return false;
    for (int i = 0; i < nbytes; i++) {
        uint32_t v = r.regs[base_reg + (i / 4)];
        out[i] = (uint8_t)(v >> ((i % 4) * 8));
    }
    return true;
}

/* ================= 门禁与记账 ================= */
static volatile int g_opened = 0;
static volatile int g_committed = 0;
static volatile int g_poisoned = 0;
static uint8_t g_aes_key[16];
static uint8_t g_mac_key[32];

static int kkl5_anti_debug(void) {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd >= 0) {
        char buf[4096];
        int n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            char *p = strstr(buf, "TracerPid:");
            if (p && atoi(p + 10) != 0) return 1;
        }
    }
    FILE *f = fopen("/proc/self/maps", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "frida") || strstr(line, "linjector") || strstr(line, "gum-js-loop")) {
                fclose(f);
                return 2;
            }
        }
        fclose(f);
    }
    DIR *d = opendir("/proc/self/task");
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') continue;
            char path[256];
            snprintf(path, sizeof(path), "/proc/self/task/%s/comm", e->d_name);
            int t = open(path, O_RDONLY);
            if (t >= 0) {
                char c[64] = {0};
                int n = read(t, c, sizeof(c) - 1);
                close(t);
                if (n > 0 && (strstr(c, "gmain") || strstr(c, "gum-js") || strstr(c, "pool-frida"))) {
                    closedir(d);
                    return 3;
                }
            }
        }
        closedir(d);
    }
    return 0;
}

static void kkl5_refresh_keys(void) {
    /* AES 主钥：VMP 程序 A（真标记 + |kkl5_cipher）解释执行得到 */
    if (!kkl5_vm_key(kKkl5VmProgramEnc, sizeof(kKkl5VmProgramEnc), 1, g_aes_key, 16)) {
        g_poisoned = 1;
        return;
    }
    /* MAC 子钥：VMP 程序 B（真标记 + |kkl5_ascension）解释执行得到 32 字节 */
    if (!kkl5_vm_key(kKkl5VmMacEnc, sizeof(kKkl5VmMacEnc), 1, g_mac_key, 32)) {
        g_poisoned = 1;
    }
}

/* onCreate 门禁：真机 onCreate 必须由 VM 还原，patch/调试命中即投毒 */
extern "C" __attribute__((noinline)) int kkl5_on_create_gate(void) {
    if (kkl5_anti_debug() != 0) { g_poisoned = 1; return -2; }
    VmResult r;
    if (!kkl5_vm_run(kKkl5VmProgramEnc, sizeof(kKkl5VmProgramEnc), r)) { g_poisoned = 1; return -3; }
    if (!r.halted || r.steps < 100) { g_poisoned = 1; return -4; }
    bool aes_ok = true;
    for (int i = 0; i < 16; i++) {
        uint8_t got = (uint8_t)(r.regs[1 + (i / 4)] >> ((i % 4) * 8));
        if (got != kKkl5VmExpectAes[i]) aes_ok = false;
    }
    if (!aes_ok) { g_poisoned = 1; return -5; }
    kkl5_refresh_keys();
    return g_poisoned ? -6 : 0;
}

/* ================= JNI ================= */
static std::string jstr(JNIEnv *env, jstring s) {
    if (!s) return std::string();
    const char *c = env->GetStringUTFChars(s, NULL);
    std::string r = c ? c : "";
    env->ReleaseStringUTFChars(s, c);
    return r;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativeOpen(JNIEnv *env, jclass) {
    if (kkl5_anti_debug() != 0) { g_poisoned = 1; return -2; }
    kkl5_refresh_keys();
    if (g_poisoned) return -4;
    g_opened = 1;
    g_committed = 0;
    return 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativeOnCreate(JNIEnv *env, jclass, jobject) {
    int gate = kkl5_on_create_gate();
    if (gate != 0) {
        kkl5_refresh_keys();
        char buf[96];
        snprintf(buf, sizeof(buf), "FAIL:onCreate VM gate %d", gate);
        return env->NewStringUTF(buf);
    }
    if (Java_com_fatdog_reverse_Kkl5Native_nativeOpen(env, NULL) != 0)
        return env->NewStringUTF("FAIL:nativeOpen");
    return env->NewStringUTF("OK:onCreate restored from VM bytecode");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativeSign(JNIEnv *env, jclass, jint page, jlong ts) {
    if (!g_opened || g_poisoned) return env->NewStringUTF("");
    char payload[64];
    snprintf(payload, sizeof(payload), "page=%d&ts=%lld", page, (long long)ts);
    /* IV: SHA256(page|ts|mac_key) 前 16 字节，确保每页上下文绑定 */
    uint8_t seed[64];
    int sl = snprintf((char *)seed, sizeof(seed), "%d|%lld|", page, (long long)ts);
    memcpy(seed + sl, g_mac_key, 32);
    uint8_t iv[16];
    sha256(seed, sl + 32, iv);
    std::vector<uint8_t> ct = aes_cbc_encrypt(g_aes_key, iv, (const uint8_t *)payload, strlen(payload));
    char *hex = (char *)malloc(ct.size() * 2 + 1);
    to_hex(ct.data(), (int)ct.size(), hex);
    std::string enc(hex);
    free(hex);
    uint8_t mac[32];
    hmac_sha256(g_mac_key, 32, (const uint8_t *)enc.data(), enc.size(), mac);
    char machex[65];
    to_hex(mac, 32, machex);
    char out[1400];
    snprintf(out, sizeof(out), "%s|%s", enc.c_str(), machex);
    g_committed = 0;
    return env->NewStringUTF(out);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativeCommit(JNIEnv *env, jclass, jint page, jint nums) {
    if (!g_opened || g_poisoned) return -2;
    if (page < 1 || nums != 10) return -3;
    g_committed = page;
    return 0;
}

extern "C" JNIEXPORT void JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativeRollback(JNIEnv *env, jclass) {
    g_committed = 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativeStatus(JNIEnv *env, jclass) {
    char buf[256];
    VmResult r;
    bool vm_ok = kkl5_vm_run(kKkl5VmProgramEnc, sizeof(kKkl5VmProgramEnc), r) && r.halted;
    snprintf(buf, sizeof(buf),
             "onCreate gate: %s\nVM: %s (%d steps)\nledger: opened=%d committed=%d\npoisoned: %d",
             g_poisoned ? "FAIL" : "OK", vm_ok ? "halted" : "broken",
             r.steps, g_opened, g_committed, g_poisoned);
    return env->NewStringUTF(buf);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativeVerifyResponse(JNIEnv *env, jclass, jint page, jlong ts,
                                                        jstring iv, jstring d, jstring sign) {
    if (!g_opened || g_poisoned) return JNI_FALSE;
    std::string ivs = jstr(env, iv), ds = jstr(env, d), ss = jstr(env, sign);
    char formed[64];
    snprintf(formed, sizeof(formed), "%d|%lld|", page, (long long)ts);
    std::string msg = std::string(formed) + ivs + "|" + ds;
    uint8_t mac[32];
    hmac_sha256(g_mac_key, 32, (const uint8_t *)msg.data(), msg.size(), mac);
    char hex[65];
    to_hex(mac, 32, hex);
    return strcmp(hex, ss.c_str()) == 0 ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativeUnseal(JNIEnv *env, jclass, jbyteArray sealed) {
    if (!g_opened || g_poisoned) return NULL;
    jsize n = env->GetArrayLength(sealed);
    if (n <= 0) return NULL;
    std::vector<uint8_t> in((size_t)n);
    env->GetByteArrayRegion(sealed, 0, n, (jbyte *)in.data());
    std::vector<uint8_t> out;
    if (!aes_cbc_decrypt(g_aes_key, in.data(), in.size(), out)) return NULL;
    jbyteArray ret = env->NewByteArray((jsize)out.size());
    env->SetByteArrayRegion(ret, 0, (jsize)out.size(), (const jbyte *)out.data());
    return ret;
}
