/*
 * 天地秘境·迷阵 KL54：困兽犹斗——魔改平坦化 + 间接跳转 + 指令替换 + 魔改 SM4（C++ OOP 重构版）。
 *
 * 考点（难度高于 KL53）：
 *  ① ★魔改 FLA：主签名函数不再是「标准 FLA」（真实块 → 预分发块），而是在
 *     真实块之间插入 1 个**无意义中间块**（真实块 → 中间块 → 分发器），
 *     并让状态变量**异或编码**（st ^ g_mask_seed，key 是运行时不变量）。
 *     → 直接破坏「真实块的前驱都是真实块 / 每个 case 末尾 MOV state,#imm」的强特征，
 *       依赖它的 D810 / JEB 通用去混淆脚本当场失效。
 *  ② 间接跳转（真实现）：真签名与 3 个同形假副本经**函数指针表**派发，表项用
 *     g_tbl_seed 异或加密（静态看表里全是乱码地址），真入口索引由运行时派生。
 *  ③ 指令替换（真实现）：加法被等价替换为 a+b → (a^b)+((a&b)<<1)，实际参与 hex 索引计算。
 *  ④ 魔改 SM4：S 盒 4 处换值（SBOX[0x3A]↔SBOX[0x7F], SBOX[0xB2]↔SBOX[0xE8]），
 *     换值步骤被拆散进 JNI_OnLoad 的两个 case（静态看不出换了几处）。
 *  ⑤ 魔改 Base64：自定义 64 字符码表藏 SM4 钥，标准 b64decode 解不出。
 *  ⑥ 加密算法藏进虚函数类层次：Transform → BeastTransform（真身魔改 SM4）/ Cage / Coin（诱饵）。
 *  ⑦ JNI_OnLoad 整体套 switch 分发器（S 盒换值 + 密钥派生 + 跳转表封装 + 标记留存）。
 *
 * 算法（语义与 C 版逐字节一致）：
 *   enc  = hex(魔改SM4-ECB(sm4_key, "page=N&ts=T" 零填充到 32))
 *   sign = SHA256("Fatdog_beast|" + page + "|" + ts)
 *   sm4_key = SHA256("Fatdog_beast|sm4")[:16]，以魔改 Base64 串藏 .rodata
 *
 * 破解路线：
 *   ① IDA 找间接跳转（BLR Xn）→ 逆出表项解密（seed 异或）
 *   ② 逐个分析 4 个同形副本（只有一个是真签名：完整算法 + 正确标记 + 正确顺序）
 *   ③ 手工还原中间块链（真实块 → 中间块 → 真实块），剔除无意义块
 *   ④ 认出魔改 Base64 自定义码表（对比标准码表 A-Za-z0-9+/ 找差异）
 *   ⑤ 魔改 SM4 定位（认 FK 常量 a3b1bac6…，对比 S 盒差异）
 *   ⑥ Frida hook 跳转表入口观察实际目标
 *
 * 标记（真）：Fatdog_beast  — UTF-16 码元（static const，借 JNI_OnLoad 引用强制保留）。
 * 诱饵（假）：鸞鼇のø   — 一字之差陷阱（beast→cage）。
 */
#include <jni.h>
#include <stdint.h>
#include <stddef.h>
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

/* ==================== 状态编码密钥（运行时不变量，静态不直白） ==================== */
/* 主分发器与 JNI_OnLoad 都用 st ^ g_mask_seed 解码状态 —— 令标准 FLA 形态匹配失效。 */
static volatile uint32_t g_mask_seed = 0x5A5A5A5Au;

/* ==================== 魔改 Base64 藏钥 ==================== */
/* 自定义码表（标准码表循环移位），标准 b64decode 解不出 */
static const char B64_TABLE[] =
    "56789+/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234";
/* 16 字节 SM4 密钥的魔改 Base64 编码（24 字符） */
static const char KEY_B64[] = "SYbLYjdSiX6t+pVClIr1/5==";

static unsigned char g_sbox_seed[16];
static volatile int g_marks_ready = 0;

static int b64_val(char c) {
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
static void derive_marks(void) {
    unsigned char raw[16];
    int n = b64_decode(KEY_B64, (int)strlen(KEY_B64), raw);
    if (n >= 16) { memcpy(g_sbox_seed, raw, 16); g_marks_ready = 1; }
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
/* 标准 S 盒明文保留（玩家靠它对比出"被换了哪 4 处"），换值表运行时构造。 */
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
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};
static unsigned char g_sbox[256];
static volatile int g_sbox_base = 0;
static volatile int g_sbox_ready = 0;

/*
 * init_sbox_pair：把「铺底 + 4 处换值」拆成两个可分别调用的步骤，
 * JNI_OnLoad 的两个 case 各调一次 —— 静态看不出总共换了几处。
 */
static void init_sbox_pair(int which) {
    int st = 0;
    for (;;) {
        switch (st) {
        case 0:
            if (!g_sbox_base) { memcpy(g_sbox, SBOX, 256); g_sbox_base = 1; }
            st = 1; break;
        case 1:
            if (which == 0) { g_sbox[0x3A] = SBOX[0x7F]; g_sbox[0x7F] = SBOX[0x3A]; }
            else            { g_sbox[0xB2] = SBOX[0xE8]; g_sbox[0xE8] = SBOX[0xB2]; }
            st = 2; break;
        case 2:
            if (which == 1) g_sbox_ready = 1;
            st = 3; break;
        case 3: return;
        default: st = 3; break;
        }
    }
}
static void init_sbox(void) {
    if (g_sbox_ready) return;
    init_sbox_pair(0);
    init_sbox_pair(1);
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

/* ==================== SM4 轮函数「平坦化」 ==================== */
/*
 * sm4_block_flat：32 轮顺序循环被改写成 switch(st) 状态机，每轮自成一个 case。
 * 语义与顺序版本逐字节一致。
 */
static void sm4_block_flat(const unsigned char in[16], unsigned char out[16],
                           const uint32_t *rk) {
    uint32_t x[36];
    int i, r = 0, st = 0;
    for (i = 0; i < 4; i++)
        x[i] = ((uint32_t)in[i*4]<<24)|((uint32_t)in[i*4+1]<<16)
             | ((uint32_t)in[i*4+2]<<8)|(uint32_t)in[i*4+3];
    for (;;) {
        switch (st) {
        case 0:
            x[4] = x[0] ^ l1(tau(x[1] ^ x[2] ^ x[3] ^ rk[0]));
            r = 1; st = 1; break;
        case 1:
            x[r+4] = x[r] ^ l1(tau(x[r+1] ^ x[r+2] ^ x[r+3] ^ rk[r]));
            r++; st = (r < 32) ? 1 : 2; break;
        case 2:
            for (i = 0; i < 4; i++) {
                uint32_t val = x[35-i];
                out[i*4]   = (unsigned char)(val>>24);
                out[i*4+1] = (unsigned char)(val>>16);
                out[i*4+2] = (unsigned char)(val>>8);
                out[i*4+3] = (unsigned char)val;
            }
            st = 3; break;
        case 3: return;
        default: st = 0; break;
        }
    }
}

/* ==================== 指令替换（真实现，参与 hex 索引） ==================== */
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

/* ==================== 输出缓冲 ==================== */
struct Board {
    char sign_hex[65];
    char enc_hex[65];
    char msg[64];
    unsigned char plain[32];
    unsigned char enc[32];
};
static Board &board() { static Board b; return b; }

/* ==================== 面向对象：虚函数藏加密算法 ==================== */
class Transform {
public:
    Transform() : armed_(false) { memset(key_, 0, 16); }
    virtual ~Transform() { wipe(); }
    virtual const char *sigil() const = 0;                                    /* vtable 槽 1 */
    virtual void apply(const unsigned char *in, size_t n, unsigned char *out) const = 0; /* 槽 2 */
    bool armed() const { return armed_; }
protected:
    void install(const unsigned char *k, size_t n) {
        size_t m = (n < 16) ? n : 16;
        memcpy(key_, k, m);
        armed_ = true;
    }
    void wipe() { size_t i; for (i = 0; i < 16; i++) key_[i] = 0; }
    unsigned char key_[16];
    bool armed_;
};

/* 真身：魔改 SM4-ECB（换值 S 盒）。轮密钥只在构造时展开。 */
class BeastTransform : public Transform {
public:
    explicit BeastTransform(const unsigned char *k) { install(k, 16); build_rk(); }
    const char *sigil() const override { return "beast"; }
    void apply(const unsigned char *in, size_t n, unsigned char *out) const override {
        size_t off;
        for (off = 0; off + 16 <= n; off += 16)
            sm4_block_flat(in + off, out + off, rk_);
    }
private:
    void build_rk() {
        uint32_t k[36];
        int i;
        if (!g_sbox_ready) init_sbox();
        for (i = 0; i < 4; i++)
            k[i] = (((uint32_t)key_[i*4]<<24) | ((uint32_t)key_[i*4+1]<<16)
                 | ((uint32_t)key_[i*4+2]<<8) | (uint32_t)key_[i*4+3]) ^ FK[i];
        for (i = 0; i < 32; i++) {
            k[i+4] = k[i] ^ l2(tau(k[i+1] ^ k[i+2] ^ k[i+3] ^ CK[i]));
            rk_[i] = k[i+4];
        }
    }
    uint32_t rk_[32];
};

/* 诱饵：SM4 形变副本——同结构，但 CK 常量被异或改坏（结果不同） */
class CageTransform : public Transform {
public:
    explicit CageTransform(const unsigned char *k) { install(k, 16); build_rk_broken(); }
    const char *sigil() const override { return "cage"; }
    void apply(const unsigned char *in, size_t n, unsigned char *out) const override {
        size_t off;
        for (off = 0; off + 16 <= n; off += 16)
            sm4_block_flat(in + off, out + off, rk_);
    }
private:
    void build_rk_broken() {
        uint32_t k[36];
        int i;
        if (!g_sbox_ready) init_sbox();
        for (i = 0; i < 4; i++)
            k[i] = (((uint32_t)key_[i*4]<<24) | ((uint32_t)key_[i*4+1]<<16)
                 | ((uint32_t)key_[i*4+2]<<8) | (uint32_t)key_[i*4+3]) ^ FK[i];
        for (i = 0; i < 32; i++) {
            k[i+4] = k[i] ^ l2(tau(k[i+1] ^ k[i+2] ^ k[i+3] ^ (CK[i] ^ 0x5A5A5A5Au)));
            rk_[i] = k[i+4];
        }
    }
    uint32_t rk_[32];
};

/* 诱饵：LCG 驱动的伪随机流（与 SM4 无关） */
class CoinTransform : public Transform {
public:
    explicit CoinTransform(const unsigned char *k) { install(k, 16); }
    const char *sigil() const override { return "coin"; }
    void apply(const unsigned char *in, size_t n, unsigned char *out) const override {
        uint32_t s = 0x9E3779B9u;
        size_t i;
        for (i = 0; i < n; i++) {
            s = s * 1664525u + 1013904223u;
            out[i] = (unsigned char)(in[i] ^ (unsigned char)(s >> 24) ^ key_[(s >> 4) & 15]);
        }
    }
};

/* 工厂：kind 决定返回哪个派生类。三类都实例化 → 三个 vtable 都留在 .rodata（考点）。 */
enum TransformKind { kBeast = 0, kCage = 1, kCoin = 2 };

static Transform *make_transform(int kind) {
    switch (kind) {
    case kCage: return new CageTransform(g_sbox_seed);
    case kCoin: return new CoinTransform(g_sbox_seed);
    case kBeast:
    default:    return new BeastTransform(g_sbox_seed);
    }
}

/* ==================== 4 个同形签名副本（间接跳转派发） ==================== */
/* 只有 real_sign 是真签名，其余 3 个是"改坏了的完整算法"（不再是一眼假的占位）。 */
typedef void (*SignFn)(int, long long);

static void real_sign(int page, long long ts) {
    Board &B = board();
    char sign_msg[80];
    unsigned char dg[32];
    static const char *H = "0123456789abcdef";
    int i;
    snprintf(sign_msg, sizeof(sign_msg), "Fatdog_beast|%d|%lld", page, ts);
    sha256((const unsigned char *)sign_msg, (unsigned int)strlen(sign_msg), dg);
    for (i = 0; i < 32; i++) {
        B.sign_hex[2*i]   = H[dg[i] >> 4];
        B.sign_hex[2*i+1] = H[dg[i] & 0xF];
    }
    B.sign_hex[64] = 0;
}

/* 假副本 1：标记写错（beast→cage） */
static void fake_guard_sign(int page, long long ts) {
    Board &B = board();
    char sign_msg[80];
    unsigned char dg[32];
    static const char *H = "0123456789abcdef";
    int i;
    snprintf(sign_msg, sizeof(sign_msg), "鸞鼇のø|%d|%lld", page, ts);
    sha256((const unsigned char *)sign_msg, (unsigned int)strlen(sign_msg), dg);
    for (i = 0; i < 32; i++) {
        B.sign_hex[2*i]   = H[dg[i] >> 4];
        B.sign_hex[2*i+1] = H[dg[i] & 0xF];
    }
    B.sign_hex[64] = 0;
}

/* 假副本 2：拼接顺序错（ts|page 颠倒） */
static void fake_order_sign(int page, long long ts) {
    Board &B = board();
    char sign_msg[80];
    unsigned char dg[32];
    static const char *H = "0123456789abcdef";
    int i;
    snprintf(sign_msg, sizeof(sign_msg), "Fatdog_beast|%lld|%d", ts, page);
    sha256((const unsigned char *)sign_msg, (unsigned int)strlen(sign_msg), dg);
    for (i = 0; i < 32; i++) {
        B.sign_hex[2*i]   = H[dg[i] >> 4];
        B.sign_hex[2*i+1] = H[dg[i] & 0xF];
    }
    B.sign_hex[64] = 0;
}

/* 假副本 3：缺标记前缀（只哈希 page|ts） */
static void fake_prefix_sign(int page, long long ts) {
    Board &B = board();
    char sign_msg[80];
    unsigned char dg[32];
    static const char *H = "0123456789abcdef";
    int i;
    snprintf(sign_msg, sizeof(sign_msg), "%d|%lld", page, ts);
    sha256((const unsigned char *)sign_msg, (unsigned int)strlen(sign_msg), dg);
    for (i = 0; i < 32; i++) {
        B.sign_hex[2*i]   = H[dg[i] >> 4];
        B.sign_hex[2*i+1] = H[dg[i] & 0xF];
    }
    B.sign_hex[64] = 0;
}

/* ==================== 加密跳转表（XOR 加密，静态看不见目标） ==================== */
static volatile uint32_t g_tbl_seed = 0x5A5A5A5Au;
static volatile uintptr_t g_dispatch_enc[4];
static volatile int g_dispatch_ready = 0;

static void seal_dispatch_table(void) {
    SignFn fns[4];
    int i;
    fns[0] = real_sign;
    fns[1] = fake_guard_sign;
    fns[2] = fake_order_sign;
    fns[3] = fake_prefix_sign;
    for (i = 0; i < 4; i++)
        g_dispatch_enc[i] = reinterpret_cast<uintptr_t>(fns[i]) ^ (uintptr_t)g_tbl_seed;
    g_dispatch_ready = 1;
}

/* 间接派发：真入口索引由运行时派生（静态不直白），表项 XOR 解密后才拿到函数地址 */
static void indirect_sign(int page, long long ts) {
    uint32_t idx;
    SignFn fn;
    if (!g_dispatch_ready) seal_dispatch_table();
    idx = (g_tbl_seed ^ 0x5A5A5A5Au) & 3u;     /* 恒 0，但静态不可判 */
    fn = reinterpret_cast<SignFn>(g_dispatch_enc[idx] ^ (uintptr_t)g_tbl_seed);
    fn(page, ts);
}

/* ==================== 主签名函数（★魔改 FLA：真实块 → 中间块链） ==================== */
/*
 * 真实块 R0..R4 之间插入无意义中间块 M0..M2；状态变量用 g_mask_seed 异或编码。
 * 语义：拼消息 → 零填充 → 魔改 SM4 加密 → hex → 间接派发签名。
 */
static void beast_sign(int page, long long ts) {
    Board &B = board();
    static Transform *g_tf = 0;
    static const char *H = "0123456789abcdef";
    int i;
    uint32_t st;

    if (!g_marks_ready) derive_marks();
    if (!g_tf) { g_tf = make_transform(kBeast); }
    (void)g_tf->armed();

    st = 0x100u ^ g_mask_seed;
    for (;;) {
        uint32_t s = st ^ g_mask_seed;
        switch (s) {
        /* ---------- 真实块 ---------- */
        case 0x100:  /* R0：拼消息 */
            snprintf(B.msg, sizeof(B.msg), "page=%d&ts=%lld", page, (long long)ts);
            st = 0x200u ^ g_mask_seed; break;          /* → 中间块 M0 */
        case 0x200:  /* M0：无意义中间块（破坏"真实块→预分发块"的固定模式） */
            { volatile uint32_t t = 0x9E37u; t = t * 3u + 1u; }
            st = 0x101u ^ g_mask_seed; break;
        case 0x101:  /* R1：零填充到 32 */
            memset(B.plain, 0, 32);
            {
                int ml = (int)strlen(B.msg);
                if (ml > 32) ml = 32;
                memcpy(B.plain, B.msg, ml);
            }
            st = 0x201u ^ g_mask_seed; break;          /* → 中间块 M1 */
        case 0x201:  /* M1 */
            { volatile uint32_t t = 0x51EDu; t ^= t >> 7; }
            st = 0x102u ^ g_mask_seed; break;
        case 0x102:  /* R2：魔改 SM4 加密（虚派发，内部走平坦化的 SM4 轮） */
            g_tf->apply(B.plain, 32, B.enc);
            st = 0x103u ^ g_mask_seed; break;          /* 直连 R3（规律打乱，非每块都走中间块） */
        case 0x103:  /* R3：enc → hex（指令替换算索引：o = add_replaced(i, i) = 2i） */
            for (i = 0; i < 32; i++) {
                uint32_t o = add_replaced((uint32_t)i, (uint32_t)i);
                B.enc_hex[o]   = H[B.enc[i] >> 4];
                B.enc_hex[o+1] = H[B.enc[i] & 0xF];
            }
            B.enc_hex[64] = 0;
            st = 0x202u ^ g_mask_seed; break;          /* → 中间块 M2 */
        case 0x202:  /* M2 */
            { volatile uint32_t t = 0xABCDu; t = t ^ (t << 5); }
            st = 0x104u ^ g_mask_seed; break;
        case 0x104:  /* R4：间接派发签名（加密跳转表） */
            indirect_sign(page, ts);
            st = 0x105u ^ g_mask_seed; break;
        case 0x105:  /* 出口 */
            return;

        /* ---------- 虚假块 ---------- */
        case 0x3FF:  /* 提前 return（截断） */
            B.sign_hex[0] = 0;
            return;
        case 0x3FE:  /* 死循环 */
            for (;;) { }
        case 0x3FD:  /* 无意义运算后跳回入口 */
            { volatile uint32_t t = 1u; t <<= 24; }
            st = 0x100u ^ g_mask_seed; break;
        default:
            st = 0x105u ^ g_mask_seed; break;
        }
    }
}

/* ==================== JNI 接口（.cpp 里必须 extern "C"） ==================== */
extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_BeastCore_nativeSign(JNIEnv *env, jclass clazz,
                                             jint page, jlong ts) {
    (void)clazz;
    beast_sign(page, (long long)ts);
    return env->NewStringUTF(board().sign_hex);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_BeastCore_nativeEnc(JNIEnv *env, jclass clazz,
                                            jint page, jlong ts) {
    (void)clazz;
    beast_sign(page, (long long)ts);
    return env->NewStringUTF(board().enc_hex);
}

/* ==================== JNI_OnLoad（分发器：S 盒换值 + 密钥派生 + 跳转表 + 标记） ==================== */
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    uint32_t st = 0x400u ^ g_mask_seed;
    for (;;) {
        uint32_t s = st ^ g_mask_seed;
        switch (s) {
        case 0x400:  /* S 盒换值对①（0x3A↔0x7F） */
            init_sbox_pair(0);
            st = 0x401u ^ g_mask_seed; break;
        case 0x401:  /* S 盒换值对②（0xB2↔0xE8）—— 换值总处数静态看不全 */
            init_sbox_pair(1);
            st = 0x402u ^ g_mask_seed; break;
        case 0x402:  /* 密钥派生（魔改 Base64 解码）藏进状态机 */
            if (!g_marks_ready) derive_marks();
            st = 0x403u ^ g_mask_seed; break;
        case 0x403:  /* 跳转表封装（表项 XOR 加密） */
            if (!g_dispatch_ready) seal_dispatch_table();
            st = 0x404u ^ g_mask_seed; break;
        case 0x404:  /* 标记留存：引用 MARKER/DECOY 防 gc-sections 删除 */
            {
                uint32_t mp = 0x5A5A5A5Au;
                int i;
                for (i = 0; i < MARKER_LEN; i++) mp ^= ((uint32_t)MARKER[i] << (i & 7));
                for (i = 0; i < DECOY_LEN;  i++) mp ^= ((uint32_t)DECOY[i]  << (i & 7));
                g_marker_proof = mp;
            }
            st = 0x405u ^ g_mask_seed; break;
        case 0x405: return JNI_VERSION_1_6;
        case 0x4FF:  /* 虚假块（恒不可达） */
            g_marker_proof = 0;
            return 0;
        default: st = 0x405u ^ g_mask_seed; break;
        }
    }
}
