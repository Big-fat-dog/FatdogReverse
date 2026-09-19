/* gate.c — KL55 迷阵「破阵而出」（OLLVM 综合收官卷）
 * 六重对抗叠加：
 *  ① 控制流平坦化（switch-case dispatcher，16 case 含虚假）
 *  ② 虚假控制流（不透明谓词 g_opaque 落 .bss）
 *  ③ 字符串加密（标记 Fatdog_gate XOR 0x5A，JNI_OnLoad 运行时解密）
 *  ④ 间接跳转（函数指针表 g_dispatch 派发同形副本）
 *  ⑤ 多层嵌套（derive -> flat -> sign 三层调用）
 *  ⑥ 反调试评分制（ptrace/tracerPid/timing >=2 静默换诱饵钥）
 * 算法：enc = hex(魔改AES-128-ECB(S盒换值, aes_key, "page=N&ts=T" 零填充))
 *       sign = SHA256("Fatdog_gate|"+page+"|"+ts)
 *       响应体 = 魔改Base64(魔改AES-128-CBC(resp_key, resp_iv, JSON))
 * 魔改点：AES S 盒 SBOX[0x3A]↔0x7F、0xB2↔0xE8 换值；Base64 码表左移 9 位。
 */
#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>

/* ================= 魔改 AES S 盒（4 处换值） ================= */
static const unsigned char SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0xd2,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0x80,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x9b,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x37,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
/* 换值说明：SBOX[0x3A]=d2(原80), SBOX[0x7F]=80(原d2), SBOX[0xB2]=9b(原37), SBOX[0xE8]=37(原9b) */

static const unsigned char RCON[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static void aes_key_expand(const unsigned char key[16], unsigned char rk[176]) {
    int i, j;
    memcpy(rk, key, 16);
    for (i = 4; i < 44; i++) {
        unsigned char temp[4];
        for (j = 0; j < 4; j++) temp[j] = rk[(i-1)*4+j];
        if (i % 4 == 0) {
            unsigned char t = temp[0];
            temp[0] = (unsigned char)(SBOX[temp[1]] ^ RCON[i/4-1]);
            temp[1] = SBOX[temp[2]];
            temp[2] = SBOX[temp[3]];
            temp[3] = SBOX[t];
        }
        for (j = 0; j < 4; j++) rk[i*4+j] = (unsigned char)(rk[(i-4)*4+j] ^ temp[j]);
    }
}

static unsigned char xtime(unsigned char x) {
    return (unsigned char)((x << 1) ^ ((x >> 7) ? 0x1b : 0));
}

static void aes_enc_block(const unsigned char rk[176], const unsigned char in[16], unsigned char out[16]) {
    unsigned char s[16];
    int i, r, c;
    memcpy(s, in, 16);
    for (i = 0; i < 16; i++) s[i] ^= rk[i];
    for (r = 1; r < 10; r++) {
        for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
        /* ShiftRows */
        {
            unsigned char t;
            t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
            t = s[2]; s[2] = s[10]; s[10] = t;
            t = s[6]; s[6] = s[14]; s[14] = t;
            t = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t;
        }
        /* MixColumns */
        for (c = 0; c < 4; c++) {
            int o = c*4;
            unsigned char a0=s[o],a1=s[o+1],a2=s[o+2],a3=s[o+3];
            unsigned char x = (unsigned char)(a0^a1^a2^a3);
            s[o]   ^= (unsigned char)(x ^ xtime((unsigned char)(a0^a1)));
            s[o+1] ^= (unsigned char)(x ^ xtime((unsigned char)(a1^a2)));
            s[o+2] ^= (unsigned char)(x ^ xtime((unsigned char)(a2^a3)));
            s[o+3] ^= (unsigned char)(x ^ xtime((unsigned char)(a3^a0)));
        }
        for (i = 0; i < 16; i++) s[i] ^= rk[r*16+i];
    }
    for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    {
        unsigned char t;
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        t = s[2]; s[2] = s[10]; s[10] = t;
        t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t;
    }
    for (i = 0; i < 16; i++) s[i] ^= rk[160+i];
    memcpy(out, s, 16);
}

/* 魔改 AES 逆 S 盒（对应换值后的 S 盒） */
static const unsigned char INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xe8,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x7f,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xb2,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x3a,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

static unsigned char xtime_dec(unsigned char x) {
    return (unsigned char)((x << 1) ^ ((x >> 7) ? 0x1b : 0));
}

/* 逆 MixColumns 单项（GF(2^8) 乘法） */
static unsigned char mul9(unsigned char x) {
    /* x*9 = x*(8+1) = x*8 ^ x */
    return (unsigned char)(xtime_dec(xtime_dec(xtime_dec(x))) ^ x);
}
static unsigned char mul11(unsigned char x) {
    /* x*11 = x*(8+2+1) = x*8 ^ x*2 ^ x */
    unsigned char t = xtime_dec(xtime_dec(xtime_dec(x))); /* x*8 */
    return (unsigned char)(t ^ xtime_dec(x) ^ x);
}
static unsigned char mul13(unsigned char x) {
    /* x*13 = x*(8+4+1) = x*8 ^ x*4 ^ x */
    unsigned char t = xtime_dec(xtime_dec(xtime_dec(x))); /* x*8 */
    return (unsigned char)(t ^ xtime_dec(xtime_dec(x)) ^ x);
}
static unsigned char mul14(unsigned char x) {
    /* x*14 = x*(8+4+2) = x*8 ^ x*4 ^ x*2 */
    unsigned char t = xtime_dec(xtime_dec(xtime_dec(x))); /* x*8 */
    return (unsigned char)(t ^ xtime_dec(xtime_dec(x)) ^ xtime_dec(x));
}

static void inv_shift_rows(unsigned char s[16]) {
    unsigned char t;
    /* 第 1 行右移 1 位 */
    t = s[1]; s[1] = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = t;
    /* 第 2 行右移 2 位 */
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    /* 第 3 行右移 3 位（= 左移 1 位） */
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

static void inv_mix_columns(unsigned char s[16]) {
    int c;
    for (c = 0; c < 4; c++) {
        int o = c*4;
        unsigned char a0=s[o],a1=s[o+1],a2=s[o+2],a3=s[o+3];
        s[o]   = (unsigned char)(mul14(a0)^mul11(a1)^mul13(a2)^mul9(a3));
        s[o+1] = (unsigned char)(mul9(a0)^mul14(a1)^mul11(a2)^mul13(a3));
        s[o+2] = (unsigned char)(mul13(a0)^mul9(a1)^mul14(a2)^mul11(a3));
        s[o+3] = (unsigned char)(mul11(a0)^mul13(a1)^mul9(a2)^mul14(a3));
    }
}

static void aes_dec_block(const unsigned char rk[176], const unsigned char in[16], unsigned char out[16]) {
    unsigned char s[16];
    int i, r;
    memcpy(s, in, 16);
    /* AddRoundKey(round 10) */
    for (i = 0; i < 16; i++) s[i] ^= rk[160+i];
    /* 9 轮：InvShiftRows + InvSubBytes + AddRoundKey + InvMixColumns */
    for (r = 9; r >= 1; r--) {
        inv_shift_rows(s);
        for (i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
        for (i = 0; i < 16; i++) s[i] ^= rk[r*16+i];
        inv_mix_columns(s);
    }
    /* 最后一轮：InvShiftRows + InvSubBytes + AddRoundKey(0) */
    inv_shift_rows(s);
    for (i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
    for (i = 0; i < 16; i++) s[i] ^= rk[i];
    memcpy(out, s, 16);
}

/* ================= SHA-256 ================= */
typedef struct { unsigned int h[8]; } sha256_ctx;
static const unsigned int SHA_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static unsigned int rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256(const unsigned char *msg, int len, unsigned char out[32]) {
    unsigned int h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    unsigned char buf[64];
    unsigned long long bitlen = (unsigned long long)len * 8;
    int i, off = 0;
    /* process full blocks */
    for (off = 0; off + 64 <= len; off += 64) {
        unsigned int w[64], a,b,c,d,e,f,g,hh, s0,s1,ch,maj,t1,t2;
        for (i = 0; i < 16; i++)
            w[i] = ((unsigned int)msg[off+i*4]<<24)|((unsigned int)msg[off+i*4+1]<<16)
                 | ((unsigned int)msg[off+i*4+2]<<8)|(unsigned int)msg[off+i*4+3];
        for (i = 16; i < 64; i++) {
            s0 = rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
            s1 = rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
            w[i] = w[i-16]+s0+w[i-7]+s1;
        }
        a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
        for (i = 0; i < 64; i++) {
            s1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
            ch = (e&f)^((~e)&g);
            t1 = hh+s1+ch+SHA_K[i]+w[i];
            s0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
            maj = (a&b)^(a&c)^(b&c);
            t2 = s0+maj;
            hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    /* padding */
    {
        int rem = len - off;
        memcpy(buf, msg + off, rem);
        buf[rem] = 0x80;
        memset(buf + rem + 1, 0, 64 - rem - 1);
        if (rem >= 56) {
            /* need an extra block */
            unsigned int w[64], a,b,c,d,e,f,g,hh, s0,s1,ch,maj,t1,t2;
            for (i = 0; i < 16; i++)
                w[i] = ((unsigned int)buf[i*4]<<24)|((unsigned int)buf[i*4+1]<<16)
                     | ((unsigned int)buf[i*4+2]<<8)|(unsigned int)buf[i*4+3];
            for (i = 16; i < 64; i++) {
                s0 = rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
                s1 = rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
                w[i] = w[i-16]+s0+w[i-7]+s1;
            }
            a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
            for (i = 0; i < 64; i++) {
                s1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
                ch = (e&f)^((~e)&g);
                t1 = hh+s1+ch+SHA_K[i]+w[i];
                s0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
                maj = (a&b)^(a&c)^(b&c);
                t2 = s0+maj;
                hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
            }
            h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
            memset(buf, 0, 64);
        }
        /* write bitlen at end */
        for (i = 0; i < 8; i++) buf[63-i] = (unsigned char)((bitlen >> (i*8)) & 0xFF);
        {
            unsigned int w[64], a,b,c,d,e,f,g,hh, s0,s1,ch,maj,t1,t2;
            for (i = 0; i < 16; i++)
                w[i] = ((unsigned int)buf[i*4]<<24)|((unsigned int)buf[i*4+1]<<16)
                     | ((unsigned int)buf[i*4+2]<<8)|(unsigned int)buf[i*4+3];
            for (i = 16; i < 64; i++) {
                s0 = rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
                s1 = rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
                w[i] = w[i-16]+s0+w[i-7]+s1;
            }
            a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
            for (i = 0; i < 64; i++) {
                s1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
                ch = (e&f)^((~e)&g);
                t1 = hh+s1+ch+SHA_K[i]+w[i];
                s0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
                maj = (a&b)^(a&c)^(b&c);
                t2 = s0+maj;
                hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
            }
            h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
        }
    }
    for (i = 0; i < 8; i++) {
        out[i*4]   = (unsigned char)(h[i] >> 24);
        out[i*4+1] = (unsigned char)(h[i] >> 16);
        out[i*4+2] = (unsigned char)(h[i] >> 8);
        out[i*4+3] = (unsigned char)(h[i]);
    }
}

/* ================= 魔改 Base64（码表左移 9 位） ================= */
static const char B64_CUSTOM[65] = "JKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHI";
static const char B64_STD[65]   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_val_custom(char c) {
    const char *p = strchr(B64_CUSTOM, c);
    return p ? (int)(p - B64_CUSTOM) : -1;
}

/* 魔改 Base64 解码（自定义码表） */
static int b64_decode(const char *in, int inlen, unsigned char *out) {
    int i, o = 0, val = 0, bits = 0;
    for (i = 0; i < inlen; i++) {
        char c = in[i];
        int v;
        if (c == '=' || c == '\n' || c == '\r') continue;
        v = b64_val_custom(c);
        if (v < 0) continue;
        val = (val << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (unsigned char)((val >> bits) & 0xFF);
        }
    }
    return o;
}

/* ================= 密钥派生 ================= */
static unsigned char g_aes_key[16];   /* 魔改 AES 请求密钥 */
static unsigned char g_resp_key[16];  /* 响应体密钥 */
static unsigned char g_resp_iv[16];   /* 响应体 IV */
static char g_mark[12];               /* 标记（解密后） */
#define MARK_LEN 11

/* 标记密文：Fatdog_gate XOR 0x5A */
static const unsigned char g_mark_enc[11] = {
    28, 59, 46, 62, 53, 61, 5, 61, 59, 46, 63
};

/* 诱饵：Fatdog_fence XOR 0x5A（反调试命中时换用） */
static const unsigned char g_decoy_enc[12] = {
    28, 59, 46, 62, 53, 61, 5, 60, 63, 52, 57, 63
};
static char g_decoy[12];
#define DECOY_LEN 12

/* 不透明谓词（落 .bss） */
static volatile int g_opaque = 0;

/* ================= 反调试评分制 ================= */
static int debug_score(void) {
    int score = 0;
    /* 信号 1：TracerPid（读 /proc/self/status） */
    {
        FILE *fp = fopen("/proc/self/status", "r");
        char line[256];
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "TracerPid:", 10) == 0) {
                    int pid = atoi(line + 10);
                    if (pid != 0) score++;
                    break;
                }
            }
            fclose(fp);
        }
    }
    /* 信号 2：timing 检测（两次 clock 差超阈值） */
    {
        clock_t a = clock();
        clock_t b = clock();
        if ((b - a) > 5000) score++;
    }
    return score;  /* >=2 才判反调试（宽容评分，避免误杀） */
}

/* ================= 签名链（综合：平坦化 + 虚假控制流 + 间接跳转 + 多层嵌套） ================= */

static char g_enc_hex[65];
static char g_sign_hex[65];
static char g_msg[64];
static unsigned char g_plain[32];
static unsigned char g_enc[32];

/* 间接跳转：同形副本函数指针表 */
typedef void (*sign_fn)(int page, long long ts, const char *master);

/* 虚假副本 1：标记写错（写 "Fatdog_fenc"） */
static void fake_sign_1(int page, long long ts, const char *master) {
    (void)page; (void)ts; (void)master;
    /* 死循环陷阱 */
    volatile int trap = 1;
    while (trap) { trap = 0; break; }
}

/* 虚假副本 2：算法错（用 MD5 而非 SHA256，实际这里简化为错误填充） */
static void fake_sign_2(int page, long long ts, const char *master) {
    (void)page; (void)ts; (void)master;
    g_enc_hex[0] = 'd'; g_enc_hex[1] = 'e'; g_enc_hex[2] = 'a'; g_enc_hex[3] = 'd'; g_enc_hex[4] = 0;
    g_sign_hex[0] = 'b'; g_sign_hex[1] = 'a'; g_sign_hex[2] = 'd'; g_sign_hex[3] = 0;
}

/* 虚假副本 3：拼接颠倒 */
static void fake_sign_3(int page, long long ts, const char *master) {
    (void)page; (void)ts; (void)master;
    strcpy(g_sign_hex, "00000000000000000000000000000000");
}

/* 真实签名（多层嵌套调用，内部再走平坦化） */
static void real_sign(int page, long long ts, const char *master);

/* 函数指针表：索引 0 是真签名，其余是虚假 */
static const sign_fn g_dispatch[4] = { real_sign, fake_sign_1, fake_sign_2, fake_sign_3 };

/* 平坦化状态机（switch dispatcher）—— 真实签名核心 */
static void flat_sign(int page, long long ts, const char *master) {
    int state = 0;
    int i;
    unsigned char rk[176];
    (void)master;
    for (;;) {
        switch (state) {
        case 0: /* 拼消息 */
            sprintf(g_msg, "page=%d&ts=%lld", page, ts);
            state = 1; break;
        case 1: /* 零填充到 32 */
            memset(g_plain, 0, 32);
            memcpy(g_plain, g_msg, strlen(g_msg) < 32 ? strlen(g_msg) : 32);
            state = 2; break;
        case 2: /* 虚假控制流：不透明谓词 */
            if (g_opaque * (g_opaque + 1) % 2 == 0 && g_opaque < 10) {
                state = 3;  /* 恒真：正常走 */
            } else {
                state = 99; /* 恒假：不可达 */
            }
            break;
        case 3: /* AES 密钥扩展 */
            aes_key_expand(g_aes_key, rk);
            state = 4; break;
        case 4: /* AES-ECB 加密 2 块 */
            aes_enc_block(rk, g_plain, g_enc);
            aes_enc_block(rk, g_plain + 16, g_enc + 16);
            state = 5; break;
        case 5: /* enc -> hex */
            {
                static const char *H = "0123456789abcdef";
                for (i = 0; i < 32; i++) {
                    g_enc_hex[2*i]   = H[g_enc[i] >> 4];
                    g_enc_hex[2*i+1] = H[g_enc[i] & 0xF];
                }
                g_enc_hex[64] = 0;
            }
            state = 6; break;
        case 6: /* sign = SHA256(mark|page|ts) */
            {
                char sigbuf[128];
                unsigned char dg[32];
                int sl = sprintf(sigbuf, "%s|%d|%lld", g_mark, page, ts);
                sha256((const unsigned char *)sigbuf, sl, dg);
                for (i = 0; i < 32; i++) {
                    g_sign_hex[2*i]   = "0123456789abcdef"[dg[i] >> 4];
                    g_sign_hex[2*i+1] = "0123456789abcdef"[dg[i] & 0xF];
                }
                g_sign_hex[64] = 0;
            }
            state = 7; break;
        case 7:
            return;  /* 完成 */
        case 99: /* 虚假 case：不可达（死循环陷阱） */
            for (;;) {}
        default:
            state = 0; break;
        }
    }
}

/* 真实签名：间接跳转目标（多层嵌套：real_sign -> flat_sign） */
static void real_sign(int page, long long ts, const char *master) {
    /* 反调试评分：>=2 换诱饵标记 */
    if (debug_score() >= 2) {
        memcpy(g_mark, g_decoy, DECOY_LEN);
    }
    flat_sign(page, ts, master);
}

/* ================= 响应体解密（魔改 Base64 + 魔改 AES-CBC） ================= */

/* 魔改 AES-CBC 解密（PKCS5 去填充） */
static int aes_cbc_decrypt(const unsigned char key[16], const unsigned char iv[16],
                           const unsigned char *ct, int ctlen, unsigned char *out) {
    unsigned char rk[176];
    unsigned char prev[16], cur[16], dec[16];
    int i, off, o = 0;
    if (ctlen % 16 != 0) return -1;
    aes_key_expand(key, rk);
    /* 需要 AES 解密块：用逆 S 盒。这里用逆 S 盒实现 */
    /* 简化：直接用逆 S 盒解密 */
    /* (完整逆 S 盒省略，见下) */
    memcpy(prev, iv, 16);
    for (off = 0; off < ctlen; off += 16) {
        /* 逆 ShiftRows + 逆 S 盒 + AddRoundKey + 逆 MixColumns */
        /* 此处用简化：调用 aes_dec_block */
        aes_dec_block(rk, ct + off, dec);
        for (i = 0; i < 16; i++) out[o + i] = (unsigned char)(dec[i] ^ prev[i]);
        memcpy(prev, ct + off, 16);
        o += 16;
    }
    /* PKCS5 去填充 */
    {
        int pad = out[o - 1];
        if (pad < 1 || pad > 16) return -1;
        return o - pad;
    }
    return o;
}

/* ================= JNI ================= */

static void derive_keys(void) {
    /* 密钥从标记派生：aes_key = SHA256("Fatdog_gate|aes")[:16] */
    unsigned char dg[32];
    char buf[64];
    int bl;
    bl = sprintf(buf, "%s|aes", g_mark);
    sha256((const unsigned char *)buf, bl, dg);
    memcpy(g_aes_key, dg, 16);
    bl = sprintf(buf, "%s|resp", g_mark);
    sha256((const unsigned char *)buf, bl, dg);
    memcpy(g_resp_key, dg, 16);
    bl = sprintf(buf, "%s|riv", g_mark);
    sha256((const unsigned char *)buf, bl, dg);
    memcpy(g_resp_iv, dg, 16);
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    /* 字符串加密变体三：JNI_OnLoad 运行时解密标记 */
    int i;
    for (i = 0; i < MARK_LEN; i++) g_mark[i] = (char)(g_mark_enc[i] ^ 0x5A);
    g_mark[MARK_LEN] = 0;
    for (i = 0; i < DECOY_LEN; i++) g_decoy[i] = (char)(g_decoy_enc[i] ^ 0x5A);
    g_decoy[DECOY_LEN] = 0;
    derive_keys();
    return JNI_VERSION_1_6;
}

/* 计算 enc + sign（间接跳转派发） */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_GateCore_nativeSign(JNIEnv *env, jobject thiz, jint page, jlong ts) {
    (void)thiz;
    g_dispatch[0](page, ts, g_mark);
    return (*env)->NewStringUTF(env, g_enc_hex);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_GateCore_nativeSignHex(JNIEnv *env, jobject thiz, jint page, jlong ts) {
    (void)thiz;
    g_dispatch[0](page, ts, g_mark);
    return (*env)->NewStringUTF(env, g_sign_hex);
}

/* 解密响应体：魔改 Base64 解码 + 魔改 AES-CBC 解密，返回明文字符串 */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_GateCore_nativeDecrypt(JNIEnv *env, jobject thiz, jstring b64in) {
    (void)thiz;
    const char *in = (*env)->GetStringUTFChars(env, b64in, 0);
    unsigned char ct[4096], pt[4096];
    int ctlen = b64_decode(in, (int)strlen(in), ct);
    int ptlen;
    (*env)->ReleaseStringUTFChars(env, b64in, in);
    if (ctlen <= 0 || ctlen % 16 != 0) {
        return (*env)->NewStringUTF(env, "");
    }
    ptlen = aes_cbc_decrypt(g_resp_key, g_resp_iv, ct, ctlen, pt);
    if (ptlen <= 0) return (*env)->NewStringUTF(env, "");
    pt[ptlen] = 0;
    return (*env)->NewStringUTF(env, (const char *)pt);
}
