// kl39.cpp —— KL39「月下独酌」（碧落天 · dart:ffi 双向往调 + 密钥分片）
//
// 伴生 so（runtime 侧）。宿主 App 不是 Flutter 运行时，无法执行 libapp.so，
// 因此由本 so 承担"发包瞬间的加密"。**本关与其余几关的差别在密钥的存放方式**：
// 主密钥被**掰成两瓣**，一瓣在 Dart 侧（libapp.so 对象池），一瓣编进本 so，
// 运行时才拼回——只逆一侧拿不到完整密钥。
//
// 算法（摘要 + 对称，**无 HMAC**）：
//   Dart 侧：d = MD5("page=<page>&ts=<ts>")                     → 16 字节二进制
//   native 侧：enc = AES-128-ECB-PKCS7(KEY16, d)                → hex
//   KEY16 = (FRAG_DART + FRAG_C) 补零到 16 字节
//   FRAG_DART = 8 字节（载荷对象池里，哨兵 "FDK39|" 之后）
//   FRAG_C    = 3 字节（本 so 内，^0x42 藏匿）
//
// 双向：本 so 另导出 `fd_moon_enc`，供 Dart 侧 dart:ffi
// （DynamicLibrary.open + lookupFunction）直接调用；真实 Flutter 工程里，
// Blutter 的 asm/ 下能看到这个调用点与符号名。

#ifndef KL39_HOST_TEST
#include <jni.h>
#endif

#include "mt_rng.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

#ifdef ANDROID
#include <android/log.h>
#define LOG_TAG "kl39"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) printf(__VA_ARGS__)
#endif

// ============================================================
// MD5（RFC 1321）—— Dart 侧那份摘要的 native 镜像（fd_moon_enc 用）
// ============================================================
namespace md5_ns {
static inline uint32_t rotl(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

static const uint32_t K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

static const uint8_t S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

struct Ctx {
    uint32_t a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
    uint64_t len = 0;
    uint8_t buf[64] = {0};
    size_t buflen = 0;
};

static void block(Ctx& x, const uint8_t* p) {
    uint32_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] = (uint32_t)p[i*4] | ((uint32_t)p[i*4+1] << 8) |
               ((uint32_t)p[i*4+2] << 16) | ((uint32_t)p[i*4+3] << 24);
    uint32_t A = x.a, B = x.b, C = x.c, D = x.d;
    for (int i = 0; i < 64; i++) {
        uint32_t F; int g;
        if (i < 16)      { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D;          g = (3 * i + 5) % 16; }
        else             { F = C ^ (B | ~D);       g = (7 * i) % 16; }
        F = F + A + K[i] + M[g];
        A = D; D = C; C = B;
        B = B + rotl(F, S[i]);
    }
    x.a += A; x.b += B; x.c += C; x.d += D;
}

static void update(Ctx& x, const uint8_t* data, size_t len) {
    x.len += len;
    size_t off = 0;
    if (x.buflen > 0) {
        size_t need = 64 - x.buflen;
        size_t take = len < need ? len : need;
        memcpy(x.buf + x.buflen, data, take);
        x.buflen += take; off += take;
        if (x.buflen == 64) { block(x, x.buf); x.buflen = 0; }
    }
    while (off + 64 <= len) { block(x, data + off); off += 64; }
    if (off < len) { memcpy(x.buf, data + off, len - off); x.buflen = len - off; }
}

// 返回 16 字节原始摘要
static void digestRaw(const std::string& in, uint8_t out[16]) {
    Ctx x;
    update(x, reinterpret_cast<const uint8_t*>(in.data()), in.size());
    uint64_t bits = x.len * 8;
    uint8_t pad = 0x80, zero = 0x00;
    update(x, &pad, 1);
    while (x.buflen != 56) update(x, &zero, 1);
    uint8_t lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (uint8_t)((bits >> (8 * i)) & 0xFF);
    update(x, lb, 8);
    uint32_t w[4] = {x.a, x.b, x.c, x.d};
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) out[i * 4 + j] = (uint8_t)((w[i] >> (8 * j)) & 0xFF);
}

static std::string digest_hex(const std::string& in) {
    uint8_t d[16];
    digestRaw(in, d);
    static const char* H = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 16; i++) { s += H[d[i] >> 4]; s += H[d[i] & 0xF]; }
    return s;
}
} // namespace md5_ns

// ============================================================
// AES-128（加密，ECB 模式 + PKCS#7）
// ============================================================
namespace aes_ns {
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

static const uint8_t RCON[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static inline uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }

struct Ctx {
    uint8_t rk[176];
    void expand(const uint8_t key[16]) {
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
            for (int k = 0; k < 4; k++) rk[i * 4 + k] = (uint8_t)(rk[(i - 4) * 4 + k] ^ t[k]);
        }
    }
    void encryptBlock(const uint8_t in[16], uint8_t out[16]) const {
        uint8_t s[16];
        for (int i = 0; i < 16; i++) s[i] = (uint8_t)(in[i] ^ rk[i]);
        for (int round = 1; round <= 10; round++) {
            uint8_t t[16];
            for (int c = 0; c < 4; c++)
                for (int r = 0; r < 4; r++)
                    t[c * 4 + r] = SBOX[s[((c + r) % 4) * 4 + r]];
            memcpy(s, t, 16);
            if (round != 10) {
                for (int c = 0; c < 4; c++) {
                    uint8_t* p = s + c * 4;
                    uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
                    uint8_t x = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
                    p[0] ^= (uint8_t)(x ^ xtime((uint8_t)(a0 ^ a1)));
                    p[1] ^= (uint8_t)(x ^ xtime((uint8_t)(a1 ^ a2)));
                    p[2] ^= (uint8_t)(x ^ xtime((uint8_t)(a2 ^ a3)));
                    p[3] ^= (uint8_t)(x ^ xtime((uint8_t)(a3 ^ a0)));
                }
            }
            for (int i = 0; i < 16; i++) s[i] ^= rk[round * 16 + i];
        }
        memcpy(out, s, 16);
    }
};

// ECB + PKCS#7，输入按字节处理的原始数据
static std::string ecbEncryptHex(const uint8_t key[16], const uint8_t* data, size_t len) {
    Ctx ctx;
    ctx.expand(key);
    std::string buf(reinterpret_cast<const char*>(data), len);
    uint8_t pad = (uint8_t)(16 - (len % 16));
    buf.append(pad, (char)pad);
    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve(buf.size() * 2);
    for (size_t off = 0; off < buf.size(); off += 16) {
        uint8_t blk[16];
        ctx.encryptBlock(reinterpret_cast<const uint8_t*>(buf.data() + off), blk);
        for (int i = 0; i < 16; i++) { out += H[blk[i] >> 4]; out += H[blk[i] & 0xF]; }
    }
    return out;
}
} // namespace aes_ns

// ============================================================
// SHA-256（仅用于 nativeAnswer）
// ============================================================
namespace sha256_ns {
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
struct Ctx {
    uint32_t h[8]; uint64_t bitlen; uint8_t data[64]; size_t datalen;
    Ctx() { h[0]=0x6a09e667; h[1]=0xbb67ae85; h[2]=0x3c6ef372; h[3]=0xa54ff53a;
            h[4]=0x510e527f; h[5]=0x9b05688c; h[6]=0x1f83d9ab; h[7]=0x5be0cd19;
            bitlen=0; datalen=0; }
};
static void transform(Ctx& c, const uint8_t d[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)d[i*4]<<24)|((uint32_t)d[i*4+1]<<16)|((uint32_t)d[i*4+2]<<8)|d[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1 = rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
        w[i] = w[i-16]+s0+w[i-7]+s1;
    }
    uint32_t a=c.h[0],b=c.h[1],cc=c.h[2],dd=c.h[3],e=c.h[4],f=c.h[5],g=c.h[6],hh=c.h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
        uint32_t ch=(e&f)^(~e&g);
        uint32_t t1=hh+S1+ch+K[i]+w[i];
        uint32_t S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
        uint32_t mj=(a&b)^(a&cc)^(b&cc);
        uint32_t t2=S0+mj;
        hh=g; g=f; f=e; e=dd+t1; dd=cc; cc=b; b=a; a=t1+t2;
    }
    c.h[0]+=a; c.h[1]+=b; c.h[2]+=cc; c.h[3]+=dd;
    c.h[4]+=e; c.h[5]+=f; c.h[6]+=g; c.h[7]+=hh;
}
static void update(Ctx& c, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        c.data[c.datalen++] = data[i];
        if (c.datalen == 64) { transform(c, c.data); c.bitlen += 512; c.datalen = 0; }
    }
}
static std::string digest_hex(const std::string& s) {
    Ctx c;
    update(c, reinterpret_cast<const uint8_t*>(s.data()), s.size());
    uint64_t bits = c.bitlen + c.datalen * 8;
    c.data[c.datalen++] = 0x80;
    if (c.datalen > 56) { while (c.datalen < 64) c.data[c.datalen++] = 0; transform(c, c.data); c.datalen = 0; }
    while (c.datalen < 56) c.data[c.datalen++] = 0;
    for (int i = 7; i >= 0; i--) c.data[c.datalen++] = (uint8_t)((bits >> (i*8)) & 0xFF);
    transform(c, c.data);
    char out[65];
    for (int i = 0; i < 8; i++) snprintf(out + i*8, 9, "%08x", c.h[i]);
    return std::string(out, 64);
}
} // namespace sha256_ns

// ============================================================
// 密钥分片：FRAG_DART 优先从载荷对象池取；FRAG_C 编在本 so
// ============================================================
namespace key_store {

// FRAG_DART 镜像兜底：8 字节 ^0x42（volatile 防常量折叠，rule 35）
static const volatile uint8_t MIRROR_DART[] = {4,35,54,38,45,37,29,47};

// FRAG_C：3 字节 ^0x42（本 so 持有的那一瓣）
static const volatile uint8_t FRAG_C[] = {45,45,44};

// 诱饵分片（干扰用，从不参与真实请求）
static const volatile uint8_t DECOY_FRAG[] = {4,35,54,38,45,37,29,49,54,35,48};

static const char TAG[] = "FDK39|";
static const size_t TAG_LEN = sizeof(TAG) - 1;

// FRAG_DART 的字节数（对象池里那瓣的长度；另一瓣在 native）
static const size_t FRAG_DART_LEN = 8;

static std::string g_dart;
static bool g_ready = false;
static bool g_from_payload = false;

static bool locate_payload(std::string& path) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[1024];
    std::string dir;
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, "libbow.so")) continue;
        const char* sp = strchr(line, '/');
        if (!sp) break;
        std::string full(sp);
        while (!full.empty() && (full.back() == '\n' || full.back() == '\r')) full.pop_back();
        size_t slash = full.find_last_of('/');
        if (slash == std::string::npos) break;
        dir = full.substr(0, slash);
        break;
    }
    fclose(fp);
    if (dir.empty()) return false;
    path = dir + "/libapp.so";
    return true;
}

static bool read_tag_from_payload(const std::string& path, std::string& out) {
    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) return false;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0 || sz > (long)(64 * 1024 * 1024)) { fclose(fp); return false; }
    std::vector<uint8_t> buf((size_t)sz);
    size_t got = fread(buf.data(), 1, (size_t)sz, fp);
    fclose(fp);
    if (got != (size_t)sz) return false;

    for (size_t i = 0; i + TAG_LEN < got; i++) {
        if (memcmp(&buf[i], TAG, TAG_LEN) != 0) continue;
        size_t s = i + TAG_LEN;
        size_t e = s;
        while (e < got && buf[e] != '|' && buf[e] != 0 && (e - s) < 64) e++;
        if (e <= s || e >= got || buf[e] != '|') continue;
        out.assign(reinterpret_cast<const char*>(&buf[s]), e - s);
        return !out.empty();
    }
    return false;
}

// 取 Dart 侧那一瓣
static const std::string& frag_dart() {
    if (g_ready) return g_dart;
    std::string path, frag;
    if (locate_payload(path) && read_tag_from_payload(path, frag) && frag.size() >= FRAG_DART_LEN) {
        g_dart = frag.substr(0, FRAG_DART_LEN);
        g_from_payload = true;
        LOGI("KL39 FRAG_DART taken from Flutter payload object pool");
    } else {
        std::string m;
        for (size_t i = 0; i < sizeof(MIRROR_DART); i++) m += (char)(MIRROR_DART[i] ^ 0x42);
        g_dart = m;
        g_from_payload = false;
        LOGI("KL39 payload unavailable, using mirror FRAG_DART");
    }
    g_ready = true;
    return g_dart;
}

static bool from_payload() { frag_dart(); return g_from_payload; }

// 本 so 持有的那一瓣
static std::string frag_c() {
    std::string s;
    for (size_t i = 0; i < sizeof(FRAG_C); i++) s += (char)(FRAG_C[i] ^ 0x42);
    return s;
}

// 两瓣拼回主密钥
static std::string master() { return frag_dart() + frag_c(); }

// AES 密钥：主密钥补零到 16 字节
static void aes_key(uint8_t out[16]) {
    memset(out, 0, 16);
    std::string m = master();
    size_t n = m.size() < 16 ? m.size() : 16;
    memcpy(out, m.data(), n);
}

} // namespace key_store

// ============================================================
// 加密：enc = AES-128-ECB-PKCS7(KEY16, MD5("page=N&ts=T"))
// ============================================================
static std::string build_enc(int page, long long ts) {
    char head[64];
    snprintf(head, sizeof(head), "page=%d&ts=%lld", page, ts);
    uint8_t d[16];
    md5_ns::digestRaw(std::string(head), d);
    uint8_t k[16];
    key_store::aes_key(k);
    return aes_ns::ecbEncryptHex(k, d, 16);
}

// 若外部已算好摘要（Dart 侧传来的 16 字节 hex），直接用它加密
static std::string build_enc_with_d(const std::string& dHex) {
    if (dHex.size() != 32) return std::string();
    uint8_t d[16];
    for (int i = 0; i < 16; i++) {
        char c1 = dHex[i * 2], c2 = dHex[i * 2 + 1];
        auto val = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int v1 = val(c1), v2 = val(c2);
        if (v1 < 0 || v2 < 0) return std::string();
        d[i] = (uint8_t)((v1 << 4) | v2);
    }
    uint8_t k[16];
    key_store::aes_key(k);
    return aes_ns::ecbEncryptHex(k, d, 16);
}

// nativeAnswer：sha256(str(1000 数和))[:8]，SEED_KL39 = 20280715
static std::string build_answer() {
    return sha256_ns::digest_hex(std::to_string(mt_rng::kl_server_sum(20280715))).substr(0, 8);
}

// ============================================================
// 宿主自测
// ============================================================
#ifdef KL39_HOST_TEST

int main() {
    printf("md5(abc)          = %s\n", md5_ns::digest_hex("abc").c_str());
    printf("expect            = 900150983cd24fb0d6963f7d28e17f72\n");
    printf("master            = %s (FRAG_DART from %s + FRAG_C)\n",
           key_store::master().c_str(), key_store::from_payload() ? "payload" : "mirror");
    printf("enc(1,1787013761) = %s\n", build_enc(1, 1787013761LL).c_str());
    printf("expect            = cffd009355f00094f0cf7a69b5f35c8b74b22287afa36e098a4c282f985d68d6\n");
    printf("enc(7,1700000000) = %s\n", build_enc(7, 1700000000LL).c_str());
    printf("expect            = 51ece1f3a4e3198dc9ff794b835d3bf074b22287afa36e098a4c282f985d68d6\n");
    printf("via d-hex         = %s\n",
           build_enc_with_d(md5_ns::digest_hex("page=1&ts=1787013761")).c_str());
    printf("answer(KL39)      = %s\n", build_answer().c_str());
    printf("expect            = 0e84adc5\n");
    return 0;
}

#else  // ---------- JNI ----------

extern "C" {

// 供 dart:ffi 调用（Dart 侧 DynamicLibrary.open("libbow.so") + lookupFunction("fd_moon_enc")）
// 返回 enc 的 hex 字符串（静态缓冲，勿并发）
const char* fd_moon_enc(int page, long long ts) {
    static char buf[96];
    std::string s = build_enc((int)page, (long long)ts);
    snprintf(buf, sizeof(buf), "%s", s.c_str());
    return buf;
}

// Java 桥：外部（Dart 侧）已算好 md5 的 16 字节 hex，native 只负责用分片密钥加密
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterFFI_nativeEnc(JNIEnv* env, jclass clz, jint page, jlong ts,
                                             jstring dHexStr) {
    (void)clz;
    const char* c = dHexStr ? env->GetStringUTFChars(dHexStr, nullptr) : nullptr;
    std::string dHex(c ? c : "");
    if (dHexStr && c) env->ReleaseStringUTFChars(dHexStr, c);

    std::string enc;
    if (dHex.empty()) {
        enc = build_enc((int)page, (long long)ts);      // 未给摘要则本 so 自行计算
    } else {
        enc = build_enc_with_d(dHex);
    }
    return env->NewStringUTF(enc.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterFFI_nativeAnswer(JNIEnv* env, jclass clz) {
    (void)clz;
    return env->NewStringUTF(build_answer().c_str());
}

// 只读自检：只报密码原语、两瓣来源与自检结果，不含密钥明文、不判胜
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterFFI_nativeGetStatus(JNIEnv* env, jclass clz) {
    (void)clz;
    char buf[220];
    snprintf(buf, sizeof(buf),
             "密码原语:MD5 + AES-128-ECB | 密钥分片:载荷%dB + native%zuB | FRAG_DART:%s | FFI:fd_moon_enc",
             (int)key_store::FRAG_DART_LEN, sizeof(key_store::FRAG_C),
             key_store::from_payload() ? "命中" : "镜像兜底");
    return env->NewStringUTF(buf);
}

} // extern "C"

#endif
