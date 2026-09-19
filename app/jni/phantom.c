/*
 * 天地秘境·迷阵 KL52：虚实相生——虚假控制流（Bogus Control Flow）。
 *
 * 考点：OLLVM 的「虚假控制流」(Bogus Control Flow, BCF)。
 * 模拟 OLLVM BogusControlFlow.cpp 的 addBogusFlow 手法：
 *   ① 在真实签名逻辑里插入「不透明谓词」(opaque predicate)——
 *      用 .bss 段的全局变量（初始为 0，静态分析不知道值）构造恒真/恒假条件；
 *   ② 虚假分支是真实块的「克隆形变版」(createAlteredBasicBlock 的 scramble)——
 *      代码结构高度相似，但计算被故意改坏，结果不同且永不执行。
 *
 * 算法（迷阵第二关，纯 SHA256 摘要签名，不用 HMAC）：
 *   enc  = hex(SM4-ECB(sm4_key, "page=N&ts=T" 零填充到 32))
 *   sign = SHA256("Fatdog_phantom|" + page + "|" + ts)
 *   sm4_key = SHA256("Fatdog_phantom|sm4")[:16]，以 Base64 串藏 .rodata
 *
 * 破解路线：
 *   ① 把 .bss 段设为只读（Edit→Segments→Edit segment 取消 Write）触发 IDA 常量传播
 *   ② 或 D810 去虚假跳转
 *   ③ 或 angr/Miasm 符号执行记录可达块（不透明谓词与输入无关，判死真假）
 *   ④ 手工识别恒真/恒假条件剪枝
 *   ⑤ Python 复刻 SM4 + SHA256 取数
 *
 * 标记（真）：Fatdog_phantom  — UTF-16 码元（static const，借 JNI_OnLoad 引用强制保留）。
 * 诱饵（假）：Fatdog_illusion — 一字之差陷阱（phantom→illusion）。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ==================== 标记留存 ==================== */
static const jchar MARKER[] = {
    'F','a','t','d','o','g','_','p','h','a','n','t','o','m'
};
#define MARKER_LEN 14
static const jchar DECOY[] = {
    'F','a','t','d','o','g','_','i','l','l','u','s','i','o','n'
};
#define DECOY_LEN 15
static volatile uint32_t g_marker_proof = 0;

/* ==================== Base64 藏钥 ==================== */
/* 16 字节 SM4 密钥，运行时 b64decode 即得 */
static const char KEY_B64[] = "jntndxfS8B2AwhYp1MhbMw==";

static unsigned char g_sm4_key[16];
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
        if (bits >= 8) { bits -= 8; out[j++] = (unsigned char)((val >> bits) & 0xFF); }
    }
    return j;
}
static void derive_keys(void) {
    unsigned char raw[16];
    int n = b64_decode(KEY_B64, (int)strlen(KEY_B64), raw);
    if (n >= 16) { memcpy(g_sm4_key, raw, 16); g_keys_ready = 1; }
}

/* ==================== SHA-256（sign 用） ==================== */
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

/* ==================== SM4-ECB（标准 S 盒，加密） ==================== */
static const unsigned char SBOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,
    0x28,0xfb,0x2c,0x05,0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,
    0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,0x9c,0x42,0x50,0xf4,
    0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,
    0x75,0x8f,0x3f,0xa6,0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,
    0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,0x68,0x6b,0x81,0xb2,
    0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,
    0x01,0x21,0x78,0x87,0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,
    0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,0xea,0xbf,0x8a,0xd2,
    0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,
    0xf5,0x8c,0xb1,0xe3,0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,
    0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,0xd5,0xdb,0x37,0x45,
    0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,
    0x1f,0x10,0x5a,0xd8,0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,
    0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,0x89,0x69,0x97,0x4a,
    0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,
    0xd7,0xcb,0x39,0x48
};
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
    return ((uint32_t)SBOX[(w>>24)&0xFF]<<24) | ((uint32_t)SBOX[(w>>16)&0xFF]<<16)
         | ((uint32_t)SBOX[(w>>8)&0xFF]<<8)  | (uint32_t)SBOX[w&0xFF];
}
static uint32_t l1(uint32_t b) { return b ^ rl(b,2) ^ rl(b,10) ^ rl(b,18) ^ rl(b,24); }
static uint32_t l2(uint32_t b) { return b ^ rl(b,13) ^ rl(b,23); }

static void sm4_keys(uint32_t rk[32]) {
    uint32_t k[36];
    int i;
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

/* ==================== 不透明谓词（.bss 全局变量） ==================== */
/* OLLVM BCF 的关键：用 .bss 段的全局变量构造恒真/恒假条件。
 * g_opaque 初始为 0，静态分析不知道值，但运行时恒定。 */
static volatile int g_opaque_a = 0;
static volatile int g_opaque_b = 0;
static volatile int g_opaque_c = 0;

/* ==================== 输出缓冲 ==================== */
static char g_sign_hex[65];
static char g_enc_hex[65];
static char g_msg[64];
static unsigned char g_plain[32];
static unsigned char g_enc[32];

/* ==================== 虚假控制流核心 ==================== */
/*
 * phantom_sign：被 BCF 混淆的签名函数。
 * 真实逻辑：拼消息 → SM4 加密 → hex → 拼 "Fatdog_phantom|page|ts" → SHA256 → hex。
 * 每个真实块之间插入「不透明谓词」+「克隆形变块」：
 *   谓词恒真 → 走真实路径；恒假分支 → 指向形变块（永不执行，但 IDA 看到两条路）。
 * 形变块（fake_*）是真实块的计算改坏版：结构相似，结果错误。
 */

/* 虚假块：克隆 case_enc 的形变版——SM4 换成"伪加密"（直接 XOR 密钥，结构相似但结果错） */
static void fake_encrypt_never_run(void) {
    /* 永不执行（由恒假谓词保护）。这段与真实 SM4 加密结构相似，但结果是错的。 */
    int i;
    for (i = 0; i < 32; i++) g_enc[i] = g_plain[i] ^ g_sm4_key[i & 15];
}

/* 虚假块：克隆 hex 的形变版——用错误字符表 */
static void fake_hex_never_run(void) {
    /* 永不执行。用打乱的字符表，产出错误 hex。 */
    static const char *BAD = "fedcba9876543210";
    int i;
    for (i = 0; i < 32; i++) {
        g_enc_hex[2*i]   = BAD[g_enc[i] >> 4];
        g_enc_hex[2*i+1] = BAD[g_enc[i] & 0xF];
    }
    g_enc_hex[64] = 0;
}

static void phantom_sign(int page, long long ts) {
    int i;
    static const char *H = "0123456789abcdef";
    uint32_t rk[32];
    unsigned char dg[32];
    char sign_msg[80];

    if (!g_keys_ready) derive_keys();

    /* 块1：拼消息 */
    snprintf(g_msg, sizeof(g_msg), "page=%d&ts=%lld", page, ts);

    /* 不透明谓词 1（恒真）：g_opaque_a 是 .bss 全局变量 = 0，
     * 0*(0+1)%2==0 恒真，且 0<10 恒真 → 走真实路径。 */
    if (g_opaque_a * (g_opaque_a + 1) % 2 == 0 && g_opaque_a < 10) {
        /* 真实路径：拼明文零填充到 32 */
        memset(g_plain, 0, 32);
        {
            int ml = (int)strlen(g_msg);
            if (ml > 32) ml = 32;
            memcpy(g_plain, g_msg, ml);
        }
    } else {
        /* 恒假分支：形变块（永不执行） */
        fake_encrypt_never_run();
    }

    /* 块2：SM4 加密 */
    sm4_keys(rk);
    sm4_block(g_plain, g_enc, rk);
    sm4_block(g_plain + 16, g_enc + 16, rk);

    /* 不透明谓词 2（恒真）：g_opaque_b = 0，条件恒真 */
    if (g_opaque_b * (g_opaque_b + 1) % 2 == 0 && g_opaque_b < 10) {
        /* 真实路径：enc → hex */
        for (i = 0; i < 32; i++) {
            g_enc_hex[2*i]   = H[g_enc[i] >> 4];
            g_enc_hex[2*i+1] = H[g_enc[i] & 0xF];
        }
        g_enc_hex[64] = 0;
    } else {
        /* 恒假分支：形变 hex（永不执行） */
        fake_hex_never_run();
    }

    /* 块3：拼 sign 消息 */
    snprintf(sign_msg, sizeof(sign_msg), "Fatdog_phantom|%d|%lld", page, ts);

    /* 不透明谓词 3（恒真）：g_opaque_c = 0 */
    if (g_opaque_c * (g_opaque_c + 1) % 2 == 0 && g_opaque_c < 10) {
        /* 真实路径：SHA256 签名 */
        sha256((const unsigned char *)sign_msg, (unsigned int)strlen(sign_msg), dg);
    } else {
        /* 恒假分支：形变签名（永不执行）——用错误输入哈希 */
        sha256((const unsigned char *)"Fatdog_illusion", 15, dg);
    }

    /* 块4：sign → hex */
    for (i = 0; i < 32; i++) {
        g_sign_hex[2*i]   = H[dg[i] >> 4];
        g_sign_hex[2*i+1] = H[dg[i] & 0xF];
    }
    g_sign_hex[64] = 0;
}

/* ==================== JNI 接口 ==================== */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_PhantomCore_nativeSign(JNIEnv *env, jclass clazz,
                                                jint page, jlong ts) {
    (void)clazz;
    phantom_sign(page, (long long)ts);
    return (*env)->NewStringUTF(env, g_sign_hex);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_PhantomCore_nativeEnc(JNIEnv *env, jclass clazz,
                                               jint page, jlong ts) {
    (void)clazz;
    phantom_sign(page, (long long)ts);
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
