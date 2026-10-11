/* libjade.so ——「天罡北斗」（由 gen_kl9.py 生成，勿手改）
 * 手写 RC4（C++ 版），两层魔改：
 *   魔改点一：KSA 的初始 S 盒不是恒等置换 S[i]=i，而是「倒过来填充」
 *             S[i]=255-i（255,254,...,1,0）——IDA 里看 KSA 循环前的初始化：
 *             不是清零递增而是查表加载倒序填充。
 *   魔改点二：PRGA 每字节输出后再异或 16 字节循环掩码 XMASK。
 * 因此标准 RC4 解不开本关密文。
 *
 * 密钥全部运行时派生：
 *   rc4_key = sha256(<标记>|"rc4") 前 16 字节
 *   mac     = sha256(<标记>|"mac") 全 32 字节
 * 真标记存成 UTF-16 码元数组（非 static 非 const 全局），默认 strings 不显示；
 * 另有一个明文诱饵标记与一段假密文等着粗心的猎物。
 *
 * C++ 化要点（算法语义零漂移，仅承载方式升级）：
 *   - std::array 载 KSA 初排 / 掩码（进 .rodata，strings 拿不到）；
 *   - Rc4Variant 结构体打包两处魔改点，真身=倒序初排+掩码、诱饵=标准恒等+无掩码，虚派发；
 *   - Codec 抽象基类（构造派生密钥 / 析构 secure_zero）+ Rc4Codec 真身
 *     与 StdRc4Codec / DecoyCodec 两个诱饵派生类 + 工厂 make_codec；
 *   - operator^ 重载把 PRGA 的输出掩码异或藏进内联展开（F5 看不出是掩码）；
 *   - JNI 走 JNI_OnLoad + RegisterNatives 动态注册（导出仅 JNI_OnLoad，
 *     不泄漏类名/方法名）；内部函数中性化命名。
 */
#include <array>
#include <cstring>
#include <cstdio>

#ifndef M4_HOST_TEST
#include <jni.h>
#endif

/* 换血点打包：KSA 初排（256B）+ 输出掩码（16B）。真身=倒序+掩码，诱饵=恒等+无掩码。 */
struct Rc4Variant {
    std::array<unsigned char, 256> ksa;
    std::array<unsigned char, 16> mask;
};

/* 真身：KSA 初排倒过来填充（255,254,...,1,0）+ 16 字节输出掩码（本关两层魔改） */
static const Rc4Variant RC4_MOD = {
    {     0xff,0xfe,0xfd,0xfc,0xfb,0xfa,0xf9,0xf8,0xf7,0xf6,0xf5,0xf4,
    0xf3,0xf2,0xf1,0xf0,0xef,0xee,0xed,0xec,0xeb,0xea,0xe9,0xe8,
    0xe7,0xe6,0xe5,0xe4,0xe3,0xe2,0xe1,0xe0,0xdf,0xde,0xdd,0xdc,
    0xdb,0xda,0xd9,0xd8,0xd7,0xd6,0xd5,0xd4,0xd3,0xd2,0xd1,0xd0,
    0xcf,0xce,0xcd,0xcc,0xcb,0xca,0xc9,0xc8,0xc7,0xc6,0xc5,0xc4,
    0xc3,0xc2,0xc1,0xc0,0xbf,0xbe,0xbd,0xbc,0xbb,0xba,0xb9,0xb8,
    0xb7,0xb6,0xb5,0xb4,0xb3,0xb2,0xb1,0xb0,0xaf,0xae,0xad,0xac,
    0xab,0xaa,0xa9,0xa8,0xa7,0xa6,0xa5,0xa4,0xa3,0xa2,0xa1,0xa0,
    0x9f,0x9e,0x9d,0x9c,0x9b,0x9a,0x99,0x98,0x97,0x96,0x95,0x94,
    0x93,0x92,0x91,0x90,0x8f,0x8e,0x8d,0x8c,0x8b,0x8a,0x89,0x88,
    0x87,0x86,0x85,0x84,0x83,0x82,0x81,0x80,0x7f,0x7e,0x7d,0x7c,
    0x7b,0x7a,0x79,0x78,0x77,0x76,0x75,0x74,0x73,0x72,0x71,0x70,
    0x6f,0x6e,0x6d,0x6c,0x6b,0x6a,0x69,0x68,0x67,0x66,0x65,0x64,
    0x63,0x62,0x61,0x60,0x5f,0x5e,0x5d,0x5c,0x5b,0x5a,0x59,0x58,
    0x57,0x56,0x55,0x54,0x53,0x52,0x51,0x50,0x4f,0x4e,0x4d,0x4c,
    0x4b,0x4a,0x49,0x48,0x47,0x46,0x45,0x44,0x43,0x42,0x41,0x40,
    0x3f,0x3e,0x3d,0x3c,0x3b,0x3a,0x39,0x38,0x37,0x36,0x35,0x34,
    0x33,0x32,0x31,0x30,0x2f,0x2e,0x2d,0x2c,0x2b,0x2a,0x29,0x28,
    0x27,0x26,0x25,0x24,0x23,0x22,0x21,0x20,0x1f,0x1e,0x1d,0x1c,
    0x1b,0x1a,0x19,0x18,0x17,0x16,0x15,0x14,0x13,0x12,0x11,0x10,
    0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,0x07,0x06,0x05,0x04,
    0x03,0x02,0x01,0x00, },
    {     0xb6,0xa4,0xbc,0x41,0xcf,0x24,0xbf,0x7f,0xc6,0x9d,0x4b,0xd6,
    0x90,0x98,0xb2,0xa3, },
};

/* 诱饵：标准恒等初排 + 全零掩码（即标准 RC4，解不开本关密文） */
static const Rc4Variant RC4_STD = {
    { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
      16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
      32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,
      48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,
      64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,
      80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,
      96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,
      112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,
      128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,
      144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,
      160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,
      176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,
      192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,
      208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,
      224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,
      240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255 },
    { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
};

/* 真标记 UTF-16 码元：非 static 非 const 全局，防止编译器常量折叠进指令流 */
unsigned short MARK[11] = {
        0x0046, 0x0061, 0x0074, 0x0064, 0x006f, 0x0067, 0x005f, 0x0076,
        0x0065, 0x0069, 0x006c,
};

/* 明文诱饵标记：非 static 保证落盘，strings 一眼可见，一字之差 */
const char DECOY_MARK[] = "魑魅のø";

/* 假密文：用诱饵标记派生的钥加密的一段"像样"假载荷 */
static const std::array<unsigned char, 32> DECOY_BLOB = {
    0x93,0x31,0xd2,0x1f,0xf3,0xe0,0x88,0x0a,0x7d,0x2a,0xfb,0xeb,
    0x91,0x01,0x36,0xe2,0xa0,0xa4,0x25,0xe0,0x02,0xe2,0x90,0xe9,
    0x49,0x2a,0x40,0xc9,0x5b,0xf5,0xd2,0xb7,
};

/* ---------- SHA-256 / HMAC-SHA256（紧凑实现，供派生/签名复用） ---------- */

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

static inline unsigned int m4_rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }

static void m4_sha_block(unsigned int h[8], const unsigned char p[64]) {
    unsigned int w[64];
    unsigned int a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[4*i]<<24)|((unsigned int)p[4*i+1]<<16)
             | ((unsigned int)p[4*i+2]<<8)|(unsigned int)p[4*i+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = m4_rotr(w[i-15],7) ^ m4_rotr(w[i-15],18) ^ (w[i-15]>>3);
        unsigned int s1 = m4_rotr(w[i-2],17) ^ m4_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = m4_rotr(e,6)^m4_rotr(e,11)^m4_rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = m4_rotr(a,2)^m4_rotr(a,13)^m4_rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

static void m4_sha256(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned int h[8];
    unsigned int off;
    unsigned char tail[128];
    unsigned int rem, tlen, i;
    unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64)
        m4_sha_block(h, msg + off);
    rem = len - off;
    std::memset(tail, 0, sizeof(tail));
    std::memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++)
        tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    m4_sha_block(h, tail);
    if (tlen == 128) m4_sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(h[i]>>24);
        out[4*i+1] = (unsigned char)(h[i]>>16);
        out[4*i+2] = (unsigned char)(h[i]>>8);
        out[4*i+3] = (unsigned char)(h[i]);
    }
}

/* ---------- MD5（供 HMAC-MD5 使用；SHA-256 仍负责密钥派生） ---------- */

static constexpr std::array<unsigned int, 64> m4_md5_k = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

static constexpr std::array<unsigned char, 64> m4_md5_s = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

#define M4_ROTL(x,n) (((x)<<(n))|((x)>>(32-(n))))

static void m4_md5_block(unsigned int h[4], const unsigned char *p) {
    unsigned int a=h[0], b=h[1], c=h[2], d=h[3];
    unsigned int m[16], f, g, tmp, i;
    for (i = 0; i < 16; i++)
        m[i] = (unsigned int)p[4*i] | ((unsigned int)p[4*i+1] << 8) |
               ((unsigned int)p[4*i+2] << 16) | ((unsigned int)p[4*i+3] << 24);
    for (i = 0; i < 64; i++) {
        if (i < 16)      { f = (b & c) | ((~b) & d); g = i; }
        else if (i < 32) { f = (d & b) | ((~d) & c); g = (5*i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d;            g = (3*i + 5) & 15; }
        else             { f = c ^ (b | (~d));       g = (7*i) & 15; }
        tmp = d; d = c; c = b;
        b = b + M4_ROTL(a + f + m4_md5_k[i] + m[g], m4_md5_s[i]);
        a = tmp;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
}

static void m4_md5(const unsigned char *msg, unsigned int len, unsigned char out[16]) {
    unsigned int h[4], off, rem, tlen, i;
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x67452301; h[1]=0xefcdab89; h[2]=0x98badcfe; h[3]=0x10325476;
    for (off = 0; off + 64 <= len; off += 64)
        m4_md5_block(h, msg + off);
    rem = len - off;
    std::memset(tail, 0, sizeof(tail));
    std::memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    /* MD5 长度字段为 64 位【小端】（与 SHA-256 的大端相反，勿照抄） */
    for (i = 0; i < 8; i++)
        tail[tlen - 8 + i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    m4_md5_block(h, tail);
    if (tlen == 128) m4_md5_block(h, tail + 64);
    for (i = 0; i < 4; i++) {
        out[4*i]   = (unsigned char)(h[i] & 0xFF);
        out[4*i+1] = (unsigned char)((h[i] >> 8) & 0xFF);
        out[4*i+2] = (unsigned char)((h[i] >> 16) & 0xFF);
        out[4*i+3] = (unsigned char)((h[i] >> 24) & 0xFF);
    }
}

/* HMAC-MD5：消息不超过 256 字节（本关签 128 字符 hex），栈上拼装即可 */
static void m4_hmac_md5(const unsigned char *key, unsigned int klen,
                        const unsigned char *msg, unsigned int mlen,
                        unsigned char out[16]) {
    unsigned char k0[64], ipad[64], opad[64], ih[16], buf[384];
    unsigned int i;
    std::memset(k0, 0, sizeof(k0));
    if (klen > 64) m4_md5(key, klen, k0);
    else std::memcpy(k0, key, klen);
    for (i = 0; i < 64; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    if (mlen > 256) mlen = 256;
    std::memcpy(buf, ipad, 64);
    std::memcpy(buf + 64, msg, mlen);
    m4_md5(buf, 64 + mlen, ih);
    std::memcpy(buf, opad, 64);
    std::memcpy(buf + 64, ih, 16);
    m4_md5(buf, 80, out);
}

/* ---------- 运算符重载：把 PRGA 的输出掩码异或藏进内联展开 ---------- */

/* Garnish：持 16 字节循环掩码，重载 ^ 让「字节 ^ 掩码」在 F5 里展开成位运算，
 * 看不出是 RC4 的输出掩码（命名中性，不直白）。 */
struct Garnish {
    const std::array<unsigned char, 16> &m;
    unsigned int step;
    explicit Garnish(const std::array<unsigned char, 16> &mask) : m(mask), step(0) {}
};

static inline unsigned char operator^(unsigned char lhs, const Garnish &g) {
    return (unsigned char)(lhs ^ g.m[g.step & 15]);
}

/* ---------- 魔改 RC4 核心（加密解密同一函数：流异或自反） ---------- */

static void m4_rc4(const Rc4Variant &v, const unsigned char *key, int klen,
                   unsigned char *buf, int len) {
    unsigned char S[256];
    int i, j, n, t;
    std::memcpy(S, v.ksa.data(), 256);
    j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) & 0xFF;
        t = S[i]; S[i] = S[j]; S[j] = (unsigned char)t;
    }
    i = 0; j = 0;
    for (n = 0; n < len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        t = S[i]; S[i] = S[j]; S[j] = (unsigned char)t;
        Garnish g(v.mask);
        g.step = (unsigned int)n;
        buf[n] = buf[n] ^ (S[(S[i] + S[j]) & 0xFF] ^ g);
    }
}

/* 标记运行时拼装 + 派生：suffix 形如 "|rc4"/"|mask"/"|mac" */
static void m4_derive(const char *suffix, unsigned char *out, int outlen) {
    char mk[32];
    char msg[48];
    unsigned char dg[32];
    int i, n = (int)(sizeof(MARK) / sizeof(unsigned short));
    int slen = (int)std::strlen(suffix);
    for (i = 0; i < n; i++) mk[i] = (char)(MARK[i] & 0xFF);
    mk[n] = 0;
    std::memcpy(msg, mk, (size_t)n);
    std::memcpy(msg + n, suffix, (size_t)slen);
    m4_sha256((const unsigned char *)msg, (unsigned int)(n + slen), dg);
    std::memcpy(out, dg, (size_t)outlen);
}

/* ---------- hex 工具 ---------- */

static void m4_hex_encode(const unsigned char *d, int n, char *out) {
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
 * 派生类各持一套 Rc4Variant（倒序/标准初排 + 掩码），虚派发。 */
class Codec {
public:
    Codec() { std::memset(key_, 0, sizeof(key_)); }
    virtual ~Codec() { secure_zero(); }
    virtual const char *sigil() const = 0;
    virtual void crypt(const unsigned char *in, size_t n, unsigned char *out) const = 0;
protected:
    void secure_zero() { volatile unsigned char *p = key_; for (int i = 0; i < 16; i++) p[i] = 0; }
    unsigned char key_[16];
};

/* 真身：倒序初排 + 真掩码 + 真钥（本关唯一正确路径） */
class Rc4Codec : public Codec {
public:
    Rc4Codec() : v_(&RC4_MOD) {
        m4_derive("|rc4", key_, 16);
    }
    const char *sigil() const override { return "veil"; }
    void crypt(const unsigned char *in, size_t n, unsigned char *out) const override {
        std::memcpy(out, in, n);
        m4_rc4(*v_, key_, 16, out, (int)n);
    }
protected:
    const Rc4Variant *v_;
};

/* 诱饵 1：标准恒等初排 + 无掩码 + 真钥——解出来与真身不同（差初排+掩码） */
class StdRc4Codec : public Rc4Codec {
public:
    StdRc4Codec() { v_ = &RC4_STD; }
    const char *sigil() const override { return "drift"; }
};

/* 诱饵 2：倒序初排 + 真掩码 + 明文诱饵钥——解出来是 DECOY_BLOB 那套假载荷 */
class DecoyCodec : public Codec {
public:
    DecoyCodec() : v_(&RC4_MOD) {
        /* 诱饵标记是明文串，直接 sha256(诱饵|"rc4") 派生 */
        char msg[32];
        int i, n = (int)std::strlen(DECOY_MARK);
        for (i = 0; i < n; i++) msg[i] = DECOY_MARK[i];
        std::memcpy(msg + n, "|rc4", 4);
        unsigned char dg[32];
        m4_sha256((const unsigned char *)msg, (unsigned int)(n + 4), dg);
        std::memcpy(key_, dg, 16);
    }
    const char *sigil() const override { return "decoy"; }
    void crypt(const unsigned char *in, size_t n, unsigned char *out) const override {
        std::memcpy(out, in, n);
        m4_rc4(*v_, key_, 16, out, (int)n);
    }
private:
    const Rc4Variant *v_;
};

/* 工厂：kind 决定返回哪个派生类（真身 / 标准初排 / 诱饵钥） */
static Codec *make_codec(int kind) {
    if (kind == 1) return new StdRc4Codec();
    if (kind == 2) return new DecoyCodec();
    return new Rc4Codec();
}

/* ---------- 业务核心（App 与玩家对拍的是同一套实现） ---------- */

static void m4_core_enc(int page, long long ts, const char *nonce, const char *dev,
                        char hex[129]) {
    char payload[64];
    unsigned char pt[64], ct[64];
    int n, i;
    /* payload: multi-field, keys in lexicographic order (dev < nonce < page < ts) */
    n = std::snprintf(payload, sizeof(payload), "dev=%s&nonce=%s&page=%d&ts=%lld",
                      dev ? dev : "", nonce ? nonce : "", page, ts);
    if (n < 0) n = 0;
    if (n > 63) n = 63;
    std::memset(pt, 0, sizeof(pt));
    for (i = 0; i < n; i++) pt[i] = (unsigned char)payload[i];
    /* 虚派发：真身 Rc4Codec 走倒序初排 + 掩码 */
    Codec *c = make_codec(0);
    c->crypt(pt, 64, ct);
    delete c;
    m4_hex_encode(ct, 64, hex);
}

static void m4_core_sign(const char *enc, char hex[65]) {
    unsigned char mk[32], dg[16];
    size_t elen = std::strlen(enc);
    if (elen > 256) elen = 256;
    m4_derive("|mac", mk, 32);
    m4_hmac_md5(mk, 32, (const unsigned char *)enc, (unsigned int)elen, dg);
    m4_hex_encode(dg, 16, hex);
}

/* ---------- 导出面 ---------- */

/* 诱饵密文：拿去配真算法会解出一段"像样"的假载荷，别当真 */
const char *m4_swirl(void) {
    static char hex[65];
    m4_hex_encode(DECOY_BLOB.data(), 32, hex);
    return hex;
}

/* 噪声导出：无人调用，纯占位混淆（中性命名） */
static volatile unsigned int m4_sink;

int m4_weave(unsigned int x) {
    unsigned int v = x;
    int i;
    for (i = 0; i < 4; i++) v = (v ^ (v << 3)) + 0x9E3779B9U;
    m4_sink = v;
    return (int)(v & 0xFFFF);
}

unsigned int m4_drift(unsigned int x, int n) {
    unsigned int v = (n & 31) ? ((x << (n & 31)) | (x >> (32 - (n & 31)))) : x;
    m4_sink = v ^ m4_sink;
    return v;
}

#ifndef M4_HOST_TEST

/* JNI 动态注册：导出仅 JNI_OnLoad，不泄漏类名/方法名 */
static jstring m4_native_enc(JNIEnv *env, jclass clazz, jint page, jlong ts,
                             jstring nonce, jstring dev) {
    char hex[129];
    const char *n, *d;
    (void)clazz;
    if (!nonce || !dev) return env->NewStringUTF("ERR_INPUT");
    n = env->GetStringUTFChars(nonce, NULL);
    d = env->GetStringUTFChars(dev, NULL);
    if (!n || !d) return env->NewStringUTF("ERR_UTF");
    m4_core_enc((int)page, (long long)ts, n, d, hex);
    env->ReleaseStringUTFChars(nonce, n);
    env->ReleaseStringUTFChars(dev, d);
    return env->NewStringUTF(hex);
}

static jstring m4_native_sign(JNIEnv *env, jclass clazz, jstring enc) {
    char hex[65];
    const char *e;
    (void)clazz;
    if (!enc) return env->NewStringUTF("ERR_INPUT");
    e = env->GetStringUTFChars(enc, NULL);
    if (!e) return env->NewStringUTF("ERR_UTF");
    m4_core_sign(e, hex);
    env->ReleaseStringUTFChars(enc, e);
    return env->NewStringUTF(hex);
}

static const JNINativeMethod kMethods[] = {
    { "nativeEnc", "(IJLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
      (void *)m4_native_enc },
    { "nativeSign", "(Ljava/lang/String;)Ljava/lang/String;",
      (void *)m4_native_sign },
};

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;
    jclass clazz = env->FindClass("com/fatdog/reverse/Vr");
    if (!clazz) return JNI_ERR;
    if (env->RegisterNatives(clazz, kMethods,
                             sizeof(kMethods) / sizeof(kMethods[0])) != JNI_OK)
        return JNI_ERR;
    return JNI_VERSION_1_6;
}

#endif /* !M4_HOST_TEST */

#ifdef M4_HOST_TEST
/* 主机自测：c++ -std=c++17 -DM4_HOST_TEST -o jadetest jade.cpp && ./jadetest */
int main(void) {
    char enc[129], sign[65];
    unsigned char key[16], work[65];
    int i;
    m4_core_enc(1, 1787013761LL, "1a2b3c4d", "android-34", enc);
    m4_core_sign(enc, sign);
    std::printf("sample_enc  = %s\n", enc);
    std::printf("sample_sign = %s\n", sign);
    /* MD5 骨架自测：标准向量，证明骨架正确后再信 HMAC-MD5 */
    {
        unsigned char d[16]; char dh[33];
        m4_md5((const unsigned char *)"abc", 3, d);
        m4_hex_encode(d, 16, dh);
        std::printf("md5_abc     = %s (want 900150983cd24fb0d6963f7d28e17f72)\n", dh);
        m4_md5((const unsigned char *)"abcdefghijklmnopqrstuvwxyz", 26, d);
        m4_hex_encode(d, 16, dh);
        std::printf("md5_a2z     = %s (want c3fcd3d76192e4007dfb496cca67e13b)\n", dh);
    }
    std::printf("decoy_seal  = %s\n", m4_swirl());
    /* 回环：流异或自反，再跑一遍即还原 */
    m4_derive("|rc4", key, 16);
    for (i = 0; i < 64; i++) {
        char c1 = enc[2*i], c2 = enc[2*i+1];
        int hi = (c1<='9')?(c1-'0'):(c1-'a'+10);
        int lo = (c2<='9')?(c2-'0'):(c2-'a'+10);
        work[i] = (unsigned char)((hi<<4)|lo);
    }
    work[64] = 0;
    m4_rc4(RC4_MOD, key, 16, work, 64);
    std::printf("roundtrip   = %s\n", work);
    /* 虚派发自测：三个派生类各取 sigil，确认 vtable 三份且真身正确 */
    {
        Codec *c0 = make_codec(0);
        Codec *c1 = make_codec(1);
        Codec *c2 = make_codec(2);
        std::printf("codec[0].sigil = %s\n", c0->sigil());
        std::printf("codec[1].sigil = %s\n", c1->sigil());
        std::printf("codec[2].sigil = %s\n", c2->sigil());
        delete c0; delete c1; delete c2;
    }
    return 0;
}
#endif
