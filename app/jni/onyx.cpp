/* libonyx.so ——「万象归一」（由 gen_kl10.py 生成，勿手改）C++ 版
 * 双层叠加签名：sign = hex( 魔改AES-128-ECB( aes_key, 魔改SHA256(payload) ) )
 *   第一层 SHA256 变体：K 表与压缩轮全标准（认骨架看 K 表 428a2f98…），
 *     但初始 IV 整组换血为派生值，且消息填充边界从 56 前移到 48（多补一轮压缩）。
 *   第二层 AES-128：S 盒/轮结构全标准（认骨架看 S 盒 63 7c 77 7b…），
 *     但 MixColumns 系数 {2,3} 对调为 {3,2}。
 * 密钥运行时派生：iv = sha256(<标记>|"iv")；aes_key = sha256(<标记>|"key")[:16]。
 * 真标记 UTF-16 码元藏匿（strings 盲区）；明文诱饵 魑魅の錠ø 一字之差。
 *
 * C++ 化要点（算法语义零漂移，仅承载方式升级）：
 *   - std::array 载 S 盒 / K 表 / Rcon / 轮密钥（进 .rodata，strings 拿不到）；
 *   - ShaAesVariant 结构体打包两处换血点：SHA 派生 IV（8 字）+ MixColumns 系数对调；
 *   - Codec 抽象基类（构造派生密钥 / 析构 secure_zero）+ Signer 真身与
 *     StdIvSigner / StdMixSigner / DecoySigner 三个诱饵派生类 + 工厂 make_codec；
 *   - operator* 重载把 GF(2^8) 乘法（MixColumns 系数）藏进内联展开（F5 看不出）；
 *   - JNI 走 JNI_OnLoad + RegisterNatives 动态注册（导出仅 JNI_OnLoad，
 *     不泄漏类名/方法名）；内部函数中性化命名。
 */
#include <array>
#include <cstring>
#include <cstdio>

#ifndef M5_HOST_TEST
#include <jni.h>
#endif

/* 换血点打包：SHA 派生 IV（8 个 32 位字）+ MixColumns 系数对调标志。
 * 真身=派生 IV + mix_swap=true；诱饵各有偏差，虚派发到不同实现。 */
struct ShaAesVariant {
    std::array<unsigned int, 8> iv;
    bool mix_swap;
};

/* 真身：派生 IV（sha256(<标记>|"iv")）+ MixColumns {2,3}->{3,2}（本关两层魔改） */
static const ShaAesVariant SA_MOD = {
    {     0x73ef89b4u, 0x0af5ee8eu, 0xe8b0b899u, 0xcf29a4a6u,
    0xd3f84ca2u, 0x1a432274u, 0x1085334bu, 0xae051d70u, },
    true,
};

/* 诱饵 A：标准 SHA IV + MixColumns 对调——摘要层不换血，解不出 */
static const ShaAesVariant SA_STD_IV = {
    { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 },
    true,
};

/* 诱饵 B：派生 IV + 标准 MixColumns——AES 层不换血，解不出 */
static const ShaAesVariant SA_STD_MIX = {
    {     0x73ef89b4u, 0x0af5ee8eu, 0xe8b0b899u, 0xcf29a4a6u,
    0xd3f84ca2u, 0x1a432274u, 0x1085334bu, 0xae051d70u, },
    false,
};

static constexpr std::array<unsigned char, 256> SBOX = {
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

static constexpr std::array<unsigned char, 10> RCON_TAB = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static constexpr std::array<unsigned int, 64> K256 = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/* 真标记 UTF-16 码元：非 static 非 const 全局，防止编译器常量折叠进指令流 */
unsigned short MARK[14] = {
        0x0046, 0x0061, 0x0074, 0x0064, 0x006f, 0x0067, 0x005f, 0x0065,
        0x0063, 0x006c, 0x0069, 0x0070, 0x0073, 0x0065,
};

/* 明文诱饵标记：非 static 保证落盘，strings 一眼可见，一字之差 */
const char DECOY_MARK[] = "魑魅の錠ø";

/* 假密文：用诱饵标记派生的钥加密的一段"像样"假载荷 */
static const std::array<unsigned char, 32> DECOY_BLOB = {
    0x53,0x0b,0xbc,0xbf,0x3f,0x31,0x0a,0x83,0x7a,0x51,0xa9,0x36,
    0x92,0x34,0x3f,0xef,0x67,0x5d,0xd1,0x6d,0x2c,0x16,0xc1,0x58,
    0x71,0x2f,0xef,0x42,0x7c,0xd2,0xe3,0x1d,
};

/* ---------- SHA-256（紧凑实现，标准版供密钥派生、变体版供签名第一层） ---------- */

static inline unsigned int m5_rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }

static void m5_sha_block(unsigned int h[8], const unsigned char p[64]) {
    unsigned int w[64];
    unsigned int a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[4*i]<<24)|((unsigned int)p[4*i+1]<<16)
             | ((unsigned int)p[4*i+2]<<8)|(unsigned int)p[4*i+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = m5_rotr(w[i-15],7) ^ m5_rotr(w[i-15],18) ^ (w[i-15]>>3);
        unsigned int s1 = m5_rotr(w[i-2],17) ^ m5_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = m5_rotr(e,6)^m5_rotr(e,11)^m5_rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = m5_rotr(a,2)^m5_rotr(a,13)^m5_rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

/* 标准 SHA-256（仅用于密钥派生） */
static void m5_std_sha(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned int h[8];
    unsigned int off, rem, tlen, i;
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64)
        m5_sha_block(h, msg + off);
    rem = len - off;
    std::memset(tail, 0, sizeof(tail));
    std::memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++)
        tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    m5_sha_block(h, tail);
    if (tlen == 128) m5_sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(h[i]>>24);
        out[4*i+1] = (unsigned char)(h[i]>>16);
        out[4*i+2] = (unsigned char)(h[i]>>8);
        out[4*i+3] = (unsigned char)(h[i]);
    }
}

/* 变体摘要：IV 由 ShaAesVariant 提供；填充边界 48（长度域在 48..55） */
#define M5_BOUNDARY 48

static void m5_sha_variant(const ShaAesVariant &v, const unsigned char *msg,
                           unsigned int len, unsigned char out[32]) {
    unsigned int h[8];
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8ULL;
    int i;
    for (i = 0; i < 8; i++) h[i] = v.iv[i];
    if (len > M5_BOUNDARY - 1) len = M5_BOUNDARY - 1;
    std::memset(tail, 0, sizeof(tail));
    std::memcpy(tail, msg, len);
    tail[len] = 0x80;
    for (i = 0; i < 8; i++)
        tail[M5_BOUNDARY + i] = (unsigned char)((bits >> (8 * (7 - i))) & 0xFF);
    m5_sha_block(h, tail);
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(h[i]>>24);
        out[4*i+1] = (unsigned char)(h[i]>>16);
        out[4*i+2] = (unsigned char)(h[i]>>8);
        out[4*i+3] = (unsigned char)(h[i]);
    }
}

/* ---------- 运算符重载：把 GF(2^8) 乘法藏进内联展开 ---------- */

/* Gf：GF(2^8) 元素，重载 * 让「系数 × 字节」在 F5 里展开成位运算，
 * 看不出是 AES MixColumns 的 {2}/{3} 系数乘法（命名中性，不直白）。 */
struct Gf {
    unsigned char c;
    explicit Gf(unsigned char coeff) : c(coeff) {}
};

static inline unsigned char operator*(unsigned char a, const Gf &g) {
    unsigned char r = 0, x = a, b = g.c;
    while (b) {
        if (b & 1) r ^= x;
        x = (unsigned char)((x & 0x80) ? ((x << 1) ^ 0x1B) : (x << 1));
        b >>= 1;
    }
    return r;
}

/* ---------- 魔改 AES-128 加密（MixColumns {2,3} -> {3,2} 由 mix_swap 控制） ---------- */

using RoundKeys = std::array<std::array<unsigned char, 16>, 11>;

static void m5_rk_expand(const unsigned char *key, RoundKeys &rk) {
    int i, j;
    unsigned char t[4];
    std::memcpy(rk[0].data(), key, 16);
    for (i = 1; i <= 10; i++) {
        const unsigned char *p = rk[i-1].data();
        unsigned char *c = rk[i].data();
        t[0] = SBOX[p[13]] ^ RCON_TAB[i-1];
        t[1] = SBOX[p[14]];
        t[2] = SBOX[p[15]];
        t[3] = SBOX[p[12]];
        for (j = 0; j < 4; j++) c[j] = p[j] ^ t[j];
        for (j = 4; j < 16; j++) c[j] = p[j] ^ c[j-4];
    }
}

static void m5_ark(unsigned char s[16], const unsigned char k[16]) {
    int i; for (i = 0; i < 16; i++) s[i] ^= k[i];
}

static void m5_shift(unsigned char s[16]) {
    unsigned char t;
    t = s[1];  s[1] = s[5];  s[5] = s[9];  s[9] = s[13]; s[13] = t;
    t = s[2];  s[2] = s[10]; s[10] = t;
    t = s[6];  s[6] = s[14]; s[14] = t;
    t = s[3];  s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t;
}

static void m5_mix(unsigned char s[16], bool swap) {
    /* swap=true：本关魔改点，系数 {2,3} 对调为 {3,2}；swap=false：标准 */
    const unsigned char c0 = swap ? 3 : 2;
    const unsigned char c1 = swap ? 2 : 3;
    int c;
    for (c = 0; c < 4; c++) {
        unsigned char a0=s[4*c],a1=s[4*c+1],a2=s[4*c+2],a3=s[4*c+3];
        s[4*c+0] = (a0 * Gf(c0)) ^ (a1 * Gf(c1)) ^ a2 ^ a3;
        s[4*c+1] = a0 ^ (a1 * Gf(c0)) ^ (a2 * Gf(c1)) ^ a3;
        s[4*c+2] = a0 ^ a1 ^ (a2 * Gf(c0)) ^ (a3 * Gf(c1));
        s[4*c+3] = (a0 * Gf(c1)) ^ a1 ^ a2 ^ (a3 * Gf(c0));
    }
}

static void m5_enc_block(const unsigned char *in, unsigned char *out,
                         const RoundKeys &rk, bool swap) {
    unsigned char s[16];
    int r, i;
    std::memcpy(s, in, 16);
    m5_ark(s, rk[0].data());
    for (r = 1; r <= 9; r++) {
        for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
        m5_shift(s);
        m5_mix(s, swap);
        m5_ark(s, rk[r].data());
    }
    for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    m5_shift(s);
    m5_ark(s, rk[10].data());
    std::memcpy(out, s, 16);
}

/* 标记运行时拼装 + 派生：suffix 形如 "|iv"/"|key" */
static void m5_derive(const char *suffix, unsigned char *out, int outlen) {
    char mk[32];
    char msg[48];
    unsigned char dg[32];
    int i, n = (int)(sizeof(MARK) / sizeof(unsigned short));
    int slen = (int)std::strlen(suffix);
    for (i = 0; i < n; i++) mk[i] = (char)(MARK[i] & 0xFF);
    mk[n] = 0;
    std::memcpy(msg, mk, (size_t)n);
    std::memcpy(msg + n, suffix, (size_t)slen);
    m5_std_sha((const unsigned char *)msg, (unsigned int)(n + slen), dg);
    std::memcpy(out, dg, (size_t)outlen);
}

/* ---------- hex 工具 ---------- */

static void m5_hex_encode(const unsigned char *d, int n, char *out) {
    static const char *HEX = "0123456789abcdef";
    int i;
    for (i = 0; i < n; i++) {
        out[2*i]   = HEX[d[i] >> 4];
        out[2*i+1] = HEX[d[i] & 0xF];
    }
    out[2*n] = 0;
}

/* ---------- C++ 抽象层：Codec 虚派发 + RAII 密钥生命周期 ---------- */

/* 抽象基类：构造时派生密钥，析构时 secure_zero 清场。
 * 派生类各持一套 ShaAesVariant（IV / MixColumns 对调），虚派发。 */
class Codec {
public:
    Codec() { std::memset(key_, 0, sizeof(key_)); }
    virtual ~Codec() { secure_zero(); }
    virtual const char *sigil() const = 0;
    virtual void digest(const unsigned char *in, size_t n, unsigned char out[32]) const = 0;
    virtual void seal(const unsigned char dg32[32], unsigned char out[32]) const = 0;
protected:
    void secure_zero() { volatile unsigned char *p = key_; for (int i = 0; i < 16; i++) p[i] = 0; }
    unsigned char key_[16];
};

/* 真身：派生 IV + MixColumns 对调 + 真钥（本关唯一正确路径） */
class Signer : public Codec {
public:
    Signer() : v_(&SA_MOD) {
        m5_derive("|key", key_, 16);
    }
    const char *sigil() const override { return "eclipse"; }
    void digest(const unsigned char *in, size_t n, unsigned char out[32]) const override {
        m5_sha_variant(*v_, in, (unsigned int)n, out);
    }
    void seal(const unsigned char dg32[32], unsigned char out[32]) const override {
        RoundKeys rk;
        int i;
        m5_rk_expand(key_, rk);
        for (i = 0; i < 32; i += 16)
            m5_enc_block(dg32 + i, out + i, rk, v_->mix_swap);
    }
protected:
    const ShaAesVariant *v_;
};

/* 诱饵 1：标准 SHA IV + MixColumns 对调——摘要层不换血，解不出 */
class StdIvSigner : public Signer {
public:
    StdIvSigner() { v_ = &SA_STD_IV; }
    const char *sigil() const override { return "ellipse"; }
};

/* 诱饵 2：派生 IV + 标准 MixColumns——AES 层不换血，解不出 */
class StdMixSigner : public Signer {
public:
    StdMixSigner() { v_ = &SA_STD_MIX; }
    const char *sigil() const override { return "umbra"; }
};

/* 诱饵 3：派生 IV + MixColumns 对调 + 明文诱饵钥——解出 DECOY_BLOB 那套假载荷 */
class DecoySigner : public Codec {
public:
    DecoySigner() : v_(&SA_MOD) {
        char msg[32];
        int i, n = (int)std::strlen(DECOY_MARK);
        for (i = 0; i < n; i++) msg[i] = DECOY_MARK[i];
        std::memcpy(msg + n, "|key", 4);
        unsigned char dg[32];
        m5_std_sha((const unsigned char *)msg, (unsigned int)(n + 4), dg);
        std::memcpy(key_, dg, 16);
    }
    const char *sigil() const override { return "decoy"; }
    void digest(const unsigned char *in, size_t n, unsigned char out[32]) const override {
        m5_sha_variant(*v_, in, (unsigned int)n, out);
    }
    void seal(const unsigned char dg32[32], unsigned char out[32]) const override {
        RoundKeys rk;
        int i;
        m5_rk_expand(key_, rk);
        for (i = 0; i < 32; i += 16)
            m5_enc_block(dg32 + i, out + i, rk, v_->mix_swap);
    }
private:
    const ShaAesVariant *v_;
};

/* 工厂：kind 决定返回哪个派生类（真身 / 标准IV / 标准Mix / 诱饵钥） */
static Codec *make_codec(int kind) {
    if (kind == 1) return new StdIvSigner();
    if (kind == 2) return new StdMixSigner();
    if (kind == 3) return new DecoySigner();
    return new Signer();
}

/* ---------- 业务核心（App 与玩家对拍的是同一套实现） ---------- */

/* 第一层：魔改 SHA256("nonce=<n>&page=<p>&ts=<t>") -> hex */
static void m5_core_digest(int page, long long ts, const char *nonce, char hex[65]) {
    char payload[160];
    unsigned char dg[32];
    int n;
    n = std::snprintf(payload, sizeof(payload), "nonce=%s&page=%d&ts=%lld",
                      nonce ? nonce : "", page, ts);
    if (n < 0) n = 0;
    if (n > 159) n = 159;
    payload[n] = 0;
    Codec *c = make_codec(0);
    c->digest((const unsigned char *)payload, (size_t)n, dg);
    delete c;
    m5_hex_encode(dg, 32, hex);
}

/* 第二层：魔改 AES-ECB(aes_key, digest 32B) -> hex */
static void m5_core_aes(const unsigned char dg32[32], char hex[65]) {
    unsigned char ct[32];
    Codec *c = make_codec(0);
    c->seal(dg32, ct);
    delete c;
    m5_hex_encode(ct, 32, hex);
}

/* ---------- 导出面 ---------- */

/* 诱饵密文：拿去配真算法会解出一段"像样"的假载荷，别当真 */
const char *m5_swirl(void) {
    static char hex[65];
    m5_hex_encode(DECOY_BLOB.data(), 32, hex);
    return hex;
}

/* 噪声导出：无人调用，纯占位混淆（中性命名） */
static volatile unsigned int m5_sink;

int m5_weave(unsigned int x) {
    unsigned int v = x;
    int i;
    for (i = 0; i < 4; i++) v = (v ^ (v << 3)) + 0x9E3779B9U;
    m5_sink = v;
    return (int)(v & 0xFFFF);
}

unsigned int m5_drift(unsigned int x, int n) {
    unsigned int v = (n & 31) ? ((x << (n & 31)) | (x >> (32 - (n & 31)))) : x;
    m5_sink = v ^ m5_sink;
    return v;
}

#ifndef M5_HOST_TEST

/* JNI 动态注册：导出仅 JNI_OnLoad，不泄漏类名/方法名 */
static jstring m5_native_digest(JNIEnv *env, jclass clazz, jint page, jlong ts,
                                jstring nonce) {
    char hex[65];
    const char *n;
    (void)clazz;
    if (!nonce) return env->NewStringUTF("ERR_INPUT");
    n = env->GetStringUTFChars(nonce, NULL);
    if (!n) return env->NewStringUTF("ERR_UTF");
    m5_core_digest((int)page, (long long)ts, n, hex);
    env->ReleaseStringUTFChars(nonce, n);
    return env->NewStringUTF(hex);
}

static jstring m5_native_sign(JNIEnv *env, jclass clazz, jstring digestHex) {
    char hex[65];
    unsigned char dg[32];
    const char *e;
    int i;
    (void)clazz;
    if (!digestHex) return env->NewStringUTF("ERR_INPUT");
    e = env->GetStringUTFChars(digestHex, NULL);
    if (!e) return env->NewStringUTF("ERR_UTF");
    for (i = 0; i < 32; i++) {
        char c1 = e[2*i], c2 = e[2*i+1];
        int hi = (c1<='9')?(c1-'0'):(c1-'a'+10);
        int lo = (c2<='9')?(c2-'0'):(c2-'a'+10);
        dg[i] = (unsigned char)((hi<<4)|lo);
    }
    env->ReleaseStringUTFChars(digestHex, e);
    m5_core_aes(dg, hex);
    return env->NewStringUTF(hex);
}

static const JNINativeMethod kMethods[] = {
    { "nativeDigest", "(IJLjava/lang/String;)Ljava/lang/String;",
      (void *)m5_native_digest },
    { "nativeSign", "(Ljava/lang/String;)Ljava/lang/String;",
      (void *)m5_native_sign },
};

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;
    jclass clazz = env->FindClass("com/fatdog/reverse/Ws");
    if (!clazz) return JNI_ERR;
    if (env->RegisterNatives(clazz, kMethods,
                             sizeof(kMethods) / sizeof(kMethods[0])) != JNI_OK)
        return JNI_ERR;
    return JNI_VERSION_1_6;
}

#endif /* !M5_HOST_TEST */

#ifdef M5_HOST_TEST
/* 主机自测：c++ -std=c++17 -DM5_HOST_TEST -o onytest onyx.cpp && ./onytest */
int main(void) {
    char dig[65], sign[65];
    m5_core_digest(1, 1787013761LL, "1a2b3c4d", dig);
    std::printf("sample_digest = %s\n", dig);
    {
        unsigned char dg[32];
        char sign2[65];
        int i;
        for (i = 0; i < 32; i++) {
            char c1 = dig[2*i], c2 = dig[2*i+1];
            int hi = (c1<='9')?(c1-'0'):(c1-'a'+10);
            int lo = (c2<='9')?(c2-'0'):(c2-'a'+10);
            dg[i] = (unsigned char)((hi<<4)|lo);
        }
        m5_core_aes(dg, sign2);
        std::printf("sample_sign   = %s\n", sign2);
    }
    std::printf("decoy_seal    = %s\n", m5_swirl());
    /* 虚派发自测：四个派生类各取 sigil，确认 vtable 四份且真身正确 */
    {
        Codec *c0 = make_codec(0);
        Codec *c1 = make_codec(1);
        Codec *c2 = make_codec(2);
        Codec *c3 = make_codec(3);
        std::printf("codec[0].sigil = %s\n", c0->sigil());
        std::printf("codec[1].sigil = %s\n", c1->sigil());
        std::printf("codec[2].sigil = %s\n", c2->sigil());
        std::printf("codec[3].sigil = %s\n", c3->sigil());
        delete c0; delete c1; delete c2; delete c3;
    }
    return 0;
}
#endif
