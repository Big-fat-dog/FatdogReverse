/*
 * libtapir.so — L53 焚天火域（Native大陆第 6 关 · 最终关）
 *
 * 主入口 · 调度 + 异常控制流 · 跨 so（dlopen libviper）+ 跨层（回调 Java）
 *
 * 静态分析视角：
 *   - 导出表只有 JNI_OnLoad（动态注册；类名/方法名/签名全是运行时解出的密文）；
 *   - dlopen 的库名、dlsym 的符号名全是密文 → 看不到 libviper.so / vp_seal 之类；
 *   - 调度类簇（TideFlow / Seal / SealNull / SealAlt / SealOne / SealTwo / SealPick）
 *     全部收进匿名命名空间，vtable/typeinfo 不进 .dynsym。
 *
 * 跨 so + 跨层密钥拼装（签名密钥）：
 *   头段 12B ← libviper.so 的 vp_mark()
 *   尾段 4B  ← Java（Bk53 递 Class → 本 so NewObject 造实例 → 回调 chip(int) 取 byte[]）
 *   → sign = HMAC-MD5(密钥, payload)；少任何一段 → 服务端 403。
 *
 * 协议：POST /api/l53 表单 page/ts/enc/aes/sign，响应 {"d": 流加密}
 * flag：FLAG_18_L53{scorched_fireland}
 */

#include <jni.h>
#include <string>
#include <cstring>
#include <cstdint>
#include <dlfcn.h>
#include <stdexcept>
#include <vector>

/* ============================================================
 * 字符串密文化（掩码走 volatile，防 -O2 常量折叠成明文）
 * ============================================================ */
static std::string decloak(const unsigned char* enc, size_t n, unsigned char mk) {
    std::string out(n, '\0');
    volatile unsigned char m = mk;
    for (size_t i = 0; i < n; i++) out[i] = (char)(enc[i] ^ m);
    return out;
}
#define DK(ARR, MK) decloak((ARR), sizeof(ARR), (unsigned char)(MK))

/* 类名 / 方法名 / 签名 / 回调锚点 / 库名 / dlsym 名 —— 构建期 XOR ^0x63 密文化 */
static const unsigned char C_CLS[] = { 0x00,0x0C,0x0E,0x4C,0x05,0x02,0x17,0x07,0x0C,0x04,0x4C,0x11,0x06,0x15,0x06,0x11,0x10,0x06,0x4C,0x21,0x08,0x56,0x50 };  // com/fatdog/reverse/Bk53
static const unsigned char C_M1[] = { 0x0D,0x02,0x17,0x0A,0x15,0x06,0x26,0x0D,0x00 };  // nativeEnc
static const unsigned char C_G1[] = { 0x4B,0x2F,0x09,0x02,0x15,0x02,0x4C,0x0F,0x02,0x0D,0x04,0x4C,0x30,0x17,0x11,0x0A,0x0D,0x04,0x58,0x2A,0x4A,0x2F,0x09,0x02,0x15,0x02,0x4C,0x0F,0x02,0x0D,0x04,0x4C,0x30,0x17,0x11,0x0A,0x0D,0x04,0x58 };  // (Ljava/lang/String;I)Ljava/lang/String;
static const unsigned char C_M2[] = { 0x0D,0x02,0x17,0x0A,0x15,0x06,0x30,0x0A,0x04,0x0D };  // nativeSign
static const unsigned char C_G2[] = { 0x4B,0x2F,0x09,0x02,0x15,0x02,0x4C,0x0F,0x02,0x0D,0x04,0x4C,0x30,0x17,0x11,0x0A,0x0D,0x04,0x58,0x4A,0x2F,0x09,0x02,0x15,0x02,0x4C,0x0F,0x02,0x0D,0x04,0x4C,0x30,0x17,0x11,0x0A,0x0D,0x04,0x58 };  // (Ljava/lang/String;)Ljava/lang/String;
static const unsigned char C_M3[] = { 0x0D,0x02,0x17,0x0A,0x15,0x06,0x31,0x00,0x57,0x27,0x06,0x00,0x11,0x1A,0x13,0x17 };  // nativeRc4Decrypt
static const unsigned char C_G3[] = { 0x4B,0x2F,0x09,0x02,0x15,0x02,0x4C,0x0F,0x02,0x0D,0x04,0x4C,0x30,0x17,0x11,0x0A,0x0D,0x04,0x58,0x4A,0x2F,0x09,0x02,0x15,0x02,0x4C,0x0F,0x02,0x0D,0x04,0x4C,0x30,0x17,0x11,0x0A,0x0D,0x04,0x58 };  // (Ljava/lang/String;)Ljava/lang/String;
static const unsigned char C_M4[] = { 0x01,0x0A,0x0D,0x07,0x28,0x06,0x1A,0x10 };  // bindKeys
static const unsigned char C_G4[] = { 0x4B,0x2F,0x09,0x02,0x15,0x02,0x4C,0x0F,0x02,0x0D,0x04,0x4C,0x20,0x0F,0x02,0x10,0x10,0x58,0x4A,0x35 };  // (Ljava/lang/Class;)V
static const unsigned char C_CB[] = { 0x00,0x0B,0x0A,0x13 };  // chip
static const unsigned char C_GB[] = { 0x4B,0x2A,0x4A,0x38,0x21 };  // (I)[B
static const unsigned char C_LIB[] = { 0x0F,0x0A,0x01,0x15,0x0A,0x13,0x06,0x11,0x4D,0x10,0x0C };  // libviper.so
static const unsigned char C_LIBD[] = { 0x0F,0x0A,0x01,0x00,0x16,0x10,0x17,0x0C,0x0E,0x10,0x4D,0x10,0x0C };  // libcustoms.so
static const unsigned char C_D1[] = { 0x15,0x13,0x3C,0x0E,0x02,0x11,0x08 };  // vp_mark
static const unsigned char C_D2[] = { 0x15,0x13,0x3C,0x10,0x06,0x02,0x0F };  // vp_seal
static const unsigned char C_D3[] = { 0x15,0x13,0x3C,0x14,0x11,0x02,0x13 };  // vp_wrap
static const unsigned char C_D4[] = { 0x15,0x13,0x3C,0x10,0x17,0x11,0x06,0x02,0x0E };  // vp_stream

/* 诱饵标记（明文可见，strings 可抓） */
static const char FAKE_MARK[] = "Fatdog_ember";

// ==================== dlopen 函数指针类型 ====================
typedef const uint8_t* (*get_key_func)();
typedef int (*feistel_core_fn)(const uint8_t*, int, uint8_t*, int, int*);
typedef int (*rc4_core_fn)(const uint8_t*, int, uint8_t*, int, int*);
typedef int (*aes_variant_core_fn)(const uint8_t*, int, uint8_t*, int, int*);

// ==================== 加密核心（前置声明，定义在本节之后的辅助函数区） ====================
static std::string core_one(const std::string& data);
static std::string core_two(const std::string& data);

/* ============================================================
 * 调度 / 异常 / vtable 分发的类簇 —— 全部收进匿名命名空间：
 * 具名作用域下的多态类会把 vtable/typeinfo/析构写进 .dynsym
 * （nm -D 一眼看到 FeistelEngine 之类），匿名化后导出表全清。
 * ============================================================ */
namespace {

// 异常控制流：真逻辑藏在 catch 块里——IDA 看 try 块是空的，必须跟到 catch
class TideFlow {
public:
    std::string flow(const std::string& input) {
        try {
            // try 块：看似无意义的运算，实际是触发异常的引子
            volatile int trigger = 0;
            if (input.size() > 0) {
                // 正常路径：不会触发异常
                throw std::runtime_error("flow_control");
            }
            return "";
        } catch (const std::runtime_error& e) {
            // 真逻辑在这里：对 input 做变换
            std::string result = input;
            for (size_t i = 0; i < result.size(); i++) {
                result[i] ^= 0x5A;  // 简单 XOR 变换
            }
            return result;
        } catch (...) {
            return "";
        }
    }

    // 第二层异常控制：密钥派生也藏在 catch 里
    std::string weave(const std::string& seed) {
        try {
            if (seed.empty()) throw std::invalid_argument("empty");
            // 正常路径返回空
            return "";
        } catch (const std::invalid_argument&) {
            // 真正的密钥派生
            std::string key = seed;
            for (size_t i = 0; i < key.size(); i++) {
                key[i] = key[i] ^ 0x3C;
            }
            return key;
        } catch (...) {
            return "";
        }
    }
};

// ==================== 分发接口 + vtable 分发 ====================
class Seal {
public:
    virtual ~Seal() {}
    virtual std::string run(const std::string& data) = 0;
    virtual std::string tag() const = 0;
};

// 诱饵加密器
class SealNull : public Seal {
public:
    std::string run(const std::string& data) override { return data; }
    std::string tag() const override { return "null"; }
};

// 诱饵加密器2
class SealAlt : public Seal {
    uint8_t key_;
public:
    SealAlt(uint8_t k = 0xFF) : key_(k) {}
    std::string run(const std::string& data) override {
        std::string r = data;
        for (auto& c : r) c ^= key_;
        return r;
    }
    std::string tag() const override { return "xor"; }
};

// 主路径：处理 TideFlow 输出的掩码数据
class SealOne : public Seal {
public:
    std::string run(const std::string& data) override {
        return core_one(data);
    }
    std::string tag() const override { return "one53"; }
};

// 独立变体分组路径：与主路径使用同一掩码输入，但轮结构完全不同
class SealTwo : public Seal {
public:
    std::string run(const std::string& data) override {
        return core_two(data);
    }
    std::string tag() const override { return "two53"; }
};

class SealPick {
public:
    // 根据 algo_id 创建加密器——vtable 分发
    static Seal* pick(int algo_id) {
        if (algo_id == 1) return new SealOne();
        if (algo_id == 2) return new SealTwo();
        // fallback：返回诱饵
        switch (algo_id) {
            case 0: return new SealNull();
            default: return new SealNull();
        }
    }
};

} /* anonymous namespace */

// ==================== HMAC-SHA256 ====================
static uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t sha256_h0[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
};

static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    for (int i = 0; i < 16; i++)
        W[i] = (block[i*4] << 24) | (block[i*4+1] << 16) | (block[i*4+2] << 8) | block[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(W[i-15], 7) ^ rotr32(W[i-15], 18) ^ (W[i-15] >> 3);
        uint32_t s1 = rotr32(W[i-2], 17) ^ rotr32(W[i-2], 19) ^ (W[i-2] >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }
    uint32_t a=state[0],b=state[1],c=state[2],d=state[3],e=state[4],f=state[5],g=state[6],h=state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1=rotr32(e,6)^rotr32(e,11)^rotr32(e,25), ch=(e&f)^(~e&g);
        uint32_t t1=h+S1+ch+sha256_k[i]+W[i];
        uint32_t S0=rotr32(a,2)^rotr32(a,13)^rotr32(a,22), maj=(a&b)^(a&c)^(b&c);
        uint32_t t2=S0+maj;
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;
    state[4]+=e;state[5]+=f;state[6]+=g;state[7]+=h;
}

static std::string sha256_hash(const std::string& msg) {
    uint32_t state[8]; memcpy(state, sha256_h0, sizeof(state));
    uint64_t bit_len = msg.size() * 8;
    std::string padded = msg; padded += (char)0x80;
    while (padded.size() % 64 != 56) padded += (char)0x00;
    for (int i = 7; i >= 0; i--) padded += (char)((bit_len >> (i * 8)) & 0xFF);
    for (size_t i = 0; i < padded.size(); i += 64) {
        uint8_t block[64]; memcpy(block, padded.c_str() + i, 64);
        sha256_compress(state, block);
    }
    std::string result(32, '\0');
    for (int i = 0; i < 8; i++) {
        result[i*4]=(state[i]>>24)&0xFF; result[i*4+1]=(state[i]>>16)&0xFF;
        result[i*4+2]=(state[i]>>8)&0xFF; result[i*4+3]=state[i]&0xFF;
    }
    return result;
}

/* ============================================================
 * MD5（供 HMAC-MD5 使用；SHA-256 仍负责 body 摘要）
 * 注意：MD5 是小端（长度字段亦为小端），与 SHA-256 的大端相反
 * ============================================================ */
static const unsigned int md5_k[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

static const unsigned char md5_s[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

#define MD5_ROTL(x,n) (((x)<<(n))|((x)>>(32-(n))))

static void md5_block(unsigned int h[4], const unsigned char *p) {
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
        b = b + MD5_ROTL(a + f + md5_k[i] + m[g], md5_s[i]);
        a = tmp;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
}

static void md5_digest(const unsigned char *msg, size_t len, unsigned char out[16]) {
    unsigned int h[4];
    size_t off, rem, tlen, i;
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x67452301; h[1]=0xefcdab89; h[2]=0x98badcfe; h[3]=0x10325476;
    for (off = 0; off + 64 <= len; off += 64)
        md5_block(h, msg + off);
    rem = len - off;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    /* 长度字段：64 位小端（MD5 规定，勿照抄 SHA-256 的大端写法） */
    for (i = 0; i < 8; i++)
        tail[tlen - 8 + i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    md5_block(h, tail);
    if (tlen == 128) md5_block(h, tail + 64);
    for (i = 0; i < 4; i++) {
        out[4*i]   = (unsigned char)(h[i] & 0xFF);
        out[4*i+1] = (unsigned char)((h[i] >> 8) & 0xFF);
        out[4*i+2] = (unsigned char)((h[i] >> 16) & 0xFF);
        out[4*i+3] = (unsigned char)((h[i] >> 24) & 0xFF);
    }
}

/* HMAC-MD5：消息不超过 256 字节 */
static void hmac_md5(const unsigned char *key, size_t klen,
                     const unsigned char *msg, size_t mlen,
                     unsigned char out[16]) {
    unsigned char k0[64], ipad[64], opad[64], ih[16], buf[384];
    size_t i;
    memset(k0, 0, sizeof(k0));
    if (klen > 64) md5_digest(key, klen, k0);
    else memcpy(k0, key, klen);
    for (i = 0; i < 64; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    if (mlen > 256) mlen = 256;
    memcpy(buf, ipad, 64);
    memcpy(buf + 64, msg, mlen);
    md5_digest(buf, 64 + mlen, ih);
    memcpy(buf, opad, 64);
    memcpy(buf + 64, ih, 16);
    md5_digest(buf, 80, out);
}

/* HMAC-MD5（std::string 版，与 hmac_sha256 同款结构，仅换摘要原语） */
static std::string md5_hash(const std::string& in) {
    unsigned char d[16];
    md5_digest(reinterpret_cast<const unsigned char*>(in.data()), in.size(), d);
    return std::string(reinterpret_cast<const char*>(d), 16);
}

static std::string hmac_md5(const std::string& key, const std::string& msg) {
    std::string k = key;
    if (k.size() > 64) k = md5_hash(k);
    while (k.size() < 64) k += '\0';
    std::string ipad(64, 0x36), opad(64, 0x5C);
    for (int i = 0; i < 64; i++) { ipad[i] ^= k[i]; opad[i] ^= k[i]; }
    return md5_hash(opad + md5_hash(ipad + msg));
}

static std::string hmac_sha256(const std::string& key, const std::string& msg) {
    std::string k = key.size() > 64 ? sha256_hash(key) : key;
    while (k.size() < 64) k += '\0';
    std::string ipad(64, 0x36), opad(64, 0x5C);
    for (int i = 0; i < 64; i++) { ipad[i] ^= k[i]; opad[i] ^= k[i]; }
    return sha256_hash(opad + sha256_hash(ipad + msg));
}

// ==================== 本地兜底密钥（正常由 libviper 提供） ====================
/* 签名密钥头段："Fatdog_hmac_" ^0x3C（12 字节）；尾段 "k53\0" 在 Java */
static const uint8_t K53_MARK_HEAD_XOR[] = {
    0x7a,0x5d,0x48,0x58,0x53,0x5b,0x63,0x54,
    0x51,0x5d,0x5f,0x63
};
static const uint8_t K53_XOR = 0x3C;

static std::string get_mark_head_local() {
    std::string key(12, '\0');
    volatile uint8_t m = K53_XOR;       /* volatile：防 -O2 折叠 */
    for (int i = 0; i < 12; i++) key[i] = (char)(K53_MARK_HEAD_XOR[i] ^ m);
    return key;
}

static void* g_53c_handle = nullptr;
static feistel_core_fn g_feistel_fn = nullptr;
static aes_variant_core_fn g_aes_variant_fn = nullptr;
static rc4_core_fn g_rc4_fn = nullptr;

static void ensure53cCore() {
    if (g_53c_handle) return;
    std::string lib = DK(C_LIB, 0x63);
    g_53c_handle = dlopen(lib.c_str(), RTLD_NOW);
    if (!g_53c_handle) return;
    std::string d2 = DK(C_D2, 0x63), d3 = DK(C_D3, 0x63), d4 = DK(C_D4, 0x63);
    g_feistel_fn = (feistel_core_fn)dlsym(g_53c_handle, d2.c_str());
    g_aes_variant_fn = (aes_variant_core_fn)dlsym(g_53c_handle, d3.c_str());
    g_rc4_fn = (rc4_core_fn)dlsym(g_53c_handle, d4.c_str());
}

static std::string core_one(const std::string& data) {
    ensure53cCore();
    if (!g_feistel_fn) return "";
    std::vector<uint8_t> out(data.size() + 32);
    int outLen = 0;
    if (g_feistel_fn((const uint8_t*)data.data(), (int)data.size(),
                     out.data(), (int)out.size(), &outLen) != 0 || outLen <= 0)
        return "";
    return std::string((const char*)out.data(), outLen);
}

static std::string core_two(const std::string& data) {
    ensure53cCore();
    if (!g_aes_variant_fn) return "";
    std::vector<uint8_t> out(data.size() + 32);
    int outLen = 0;
    if (g_aes_variant_fn((const uint8_t*)data.data(), (int)data.size(),
                         out.data(), (int)out.size(), &outLen) != 0 || outLen <= 0)
        return "";
    return std::string((const char*)out.data(), outLen);
}

// ==================== 深层调用栈辅助函数 ====================
static std::string k53_dispatch(int algo_id, const std::string& data) {
    // 第2层
    TideFlow handler;
    std::string processed = handler.flow(data);
    // 第3层
    Seal* cipher = SealPick::pick(algo_id);
    std::string result = cipher->run(processed);
    delete cipher;
    return result;
}

// ==================== JNI 函数（静态命名 → RegisterNatives 动态绑定） ====================
static JavaVM* g_jvm = nullptr;

/* ---------- 跨层回调：签名密钥尾段（"k53\0"）由 Java 侧供给 ---------- */
static jclass g_cls = NULL;      /* Bk53 递进来的取件器 Class */
static jmethodID g_ctor = NULL;
static jmethodID g_tail = NULL;

static const jint K53_SPOOL = 0x6B24;      /* Java 构造用盐 */
static const jint K53_MASK  = 0x1F4A62D8;  /* so 侧回调掩码：少一比特 → 乱码 */

static JNIEnv* cur_env() {
    if (g_jvm == NULL) return NULL;
    JNIEnv* env = NULL;
    if (g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return NULL;
    return env;
}

/* native 侧自己造 Java 对象（JNI 不看访问修饰符 → 可直接调私有构造） */
static std::string fetch_tail(JNIEnv* env) {
    if (env == NULL) env = cur_env();
    if (env == NULL || g_cls == NULL || g_ctor == NULL || g_tail == NULL) return std::string();
    jobject obj = env->NewObject(g_cls, g_ctor, K53_SPOOL);
    if (obj == NULL) return std::string();
    jbyteArray ja = (jbyteArray) env->CallObjectMethod(obj, g_tail, K53_MASK);
    env->DeleteLocalRef(obj);
    if (ja == NULL) return std::string();
    jsize n = env->GetArrayLength(ja);
    jbyte* b = env->GetByteArrayElements(ja, NULL);
    std::string out;
    if (b != NULL && n > 0) {
        out.assign(reinterpret_cast<const char*>(b), (size_t)n);
        env->ReleaseByteArrayElements(ja, b, JNI_ABORT);
    }
    env->DeleteLocalRef(ja);
    return out;
}

/* 拼齐 16 字节签名密钥：头段 12B（viper 或本地兜底）+ 尾段 4B（Java） */
static std::string full_mark_key(JNIEnv* env) {
    std::string head;
    std::string lib = DK(C_LIB, 0x63), sym = DK(C_D1, 0x63);
    void* handle = dlopen(lib.c_str(), RTLD_NOW);
    if (handle) {
        get_key_func fn = (get_key_func)dlsym(handle, sym.c_str());
        if (fn) {
            const uint8_t* raw = fn();
            if (raw) head.assign(reinterpret_cast<const char*>(raw), 12);
        }
        dlclose(handle);
    }
    if (head.size() != 12) head = get_mark_head_local();
    std::string tail = fetch_tail(env);
    if (tail.size() != 4) return std::string();
    return head + tail;
}

static jstring nativeSignImpl(JNIEnv* env, jobject, jstring data) {
    const char* cdata = env->GetStringUTFChars(data, nullptr);
    std::string payload = (cdata != nullptr) ? std::string(cdata) : std::string();
    if (cdata != nullptr) env->ReleaseStringUTFChars(data, cdata);

    std::string sig = hmac_md5(full_mark_key(env), payload);
    std::string hex;
    for (unsigned char c : sig) { char buf[3]; snprintf(buf, sizeof(buf), "%02x", c); hex += buf; }
    return env->NewStringUTF(hex.c_str());
}

static jstring nativeEncImpl(JNIEnv* env, jobject, jstring data, jint algo) {
    const char* cdata = env->GetStringUTFChars(data, nullptr);
    std::string input = (cdata != nullptr) ? std::string(cdata) : std::string();
    if (cdata != nullptr) env->ReleaseStringUTFChars(data, cdata);

    // 深层调用栈：JNI → k53_dispatch → TideFlow::flow → SealPick::pick → Seal::run
    std::string enc = k53_dispatch(algo, input);

    std::string hex;
    for (unsigned char c : enc) { char buf[3]; snprintf(buf, sizeof(buf), "%02x", c); hex += buf; }
    return env->NewStringUTF(hex.c_str());
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static jstring nativeRc4Impl(JNIEnv* env, jobject, jstring hexData) {
    const char* cdata = env->GetStringUTFChars(hexData, nullptr);
    std::string hex = (cdata != nullptr) ? std::string(cdata) : std::string();
    if (cdata != nullptr) env->ReleaseStringUTFChars(hexData, cdata);
    if (hex.size() % 2 != 0) return env->NewStringUTF("");
    std::vector<uint8_t> in(hex.size() / 2);
    for (size_t i = 0; i < in.size(); i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return env->NewStringUTF("");
        in[i] = (uint8_t)((hi << 4) | lo);
    }
    ensure53cCore();
    if (!g_rc4_fn) return env->NewStringUTF("");
    std::vector<uint8_t> out(in.size());
    int outLen = 0;
    if (g_rc4_fn(in.data(), (int)in.size(), out.data(), (int)out.size(), &outLen) != 0 || outLen <= 0)
        return env->NewStringUTF("");
    std::string plain((const char*)out.data(), outLen);
    return env->NewStringUTF(plain.c_str());
}

/* 跨层桥：Bk53 递进取件器的 Class，本 so NewObject 造实例 + 回调 */
static void implBind(JNIEnv* env, jclass, jclass holder) {
    if (g_cls != NULL) { env->DeleteGlobalRef(g_cls); g_cls = NULL; }
    g_ctor = g_tail = NULL;
    if (holder == NULL) return;
    g_cls = (jclass) env->NewGlobalRef(holder);
    if (g_cls == NULL) return;
    std::string ct = DK(C_CB, 0x63);
    std::string gb = DK(C_GB, 0x63);
    g_ctor = env->GetMethodID(g_cls, "<init>", "(I)V");
    g_tail = env->GetMethodID(g_cls, ct.c_str(), gb.c_str());
}

/* 诱饵导出：Java 侧根本没声明这个方法 —— 纯误导 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk53_nativeTapir(JNIEnv* env, jclass) {
    return env->NewStringUTF(FAKE_MARK);
}

// ==================== RegisterNatives 动态绑定 ====================
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_jvm = vm;
    JNIEnv* env = cur_env();
    if (env != NULL) {
        std::string cls = DK(C_CLS, 0x63);
        jclass c = env->FindClass(cls.c_str());
        if (c != NULL) {
            std::string n1 = DK(C_M1, 0x63), g1 = DK(C_G1, 0x63);
            std::string n2 = DK(C_M2, 0x63), g2 = DK(C_G2, 0x63);
            std::string n3 = DK(C_M3, 0x63), g3 = DK(C_G3, 0x63);
            std::string n4 = DK(C_M4, 0x63), g4 = DK(C_G4, 0x63);
            JNINativeMethod m[4];
            m[0].name = const_cast<char*>(n1.c_str()); m[0].signature = const_cast<char*>(g1.c_str()); m[0].fnPtr = (void*)nativeEncImpl;
            m[1].name = const_cast<char*>(n2.c_str()); m[1].signature = const_cast<char*>(g2.c_str()); m[1].fnPtr = (void*)nativeSignImpl;
            m[2].name = const_cast<char*>(n3.c_str()); m[2].signature = const_cast<char*>(g3.c_str()); m[2].fnPtr = (void*)nativeRc4Impl;
            m[3].name = const_cast<char*>(n4.c_str()); m[3].signature = const_cast<char*>(g4.c_str()); m[3].fnPtr = (void*)implBind;
            if (env->RegisterNatives(c, m, 4) != JNI_OK && env->ExceptionCheck())
                env->ExceptionClear();
        } else if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
    }
    /* 干扰 so：仅 dlopen 进进程（/proc/self/maps 可见、dlopen-trace 可捕获），不 dlsym 不调用 */
    std::string decoy = DK(C_LIBD, 0x63);
    (void)dlopen(decoy.c_str(), RTLD_NOW);
    return JNI_VERSION_1_6;
}
