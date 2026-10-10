// kl40b.cpp —— KL40b「镜中之障」（碧落天 · 引擎层证书校验 / reFlutter 等价）
//
// 伴生 so（runtime 侧）。宿主 App 不是 Flutter 运行时，无法执行 libflutter.so；
// 真实 Flutter 的证书链校验在 libflutter.so 内嵌的 BoringSSL
// （ssl_crypto_x509_session_verify_cert_chain）里，Java / native hook 都够不着。
// 本 so 在**与 BoringSSL 相同的位置**放一个"引擎校验桩"（static、**不导出符号**）：
//   - 桩原始返回 0（证书链不可信）→ 发包参数被静默投毒，取不到数；
//   - 须以 reFlutter / Frida pattern-scan 手法把桩改成恒真（mov w0,#1; ret），
//     或静态复刻算法自行直连，才能拿到真数据。
//
// 本关算法（流密码 + 摘要，**无 HMAC**）：
//   KEY     = base64_decode(<载荷/镜像里的 base64 串>)   （密钥以 base64 承载）
//   kstream = SHA256(KEY + "|rc4")
//   enc     = hex(RC4(kstream, "page=<page>&ts=<ts>"))     （流密码，长度不变）
//   sign    = md5(enc + KEY)
//
// 密钥以真实 Flutter 载荷 libapp.so 的对象池为准（同 KL36/38 口径），**且以 base64 承载**：
//   1) 按 /proc/self/maps 定位自身所在目录，读同目录的 libapp.so；
//   2) 搜哨兵 "FDK4B|"，取到下一个 '|' 之间的字符串——它是**主密钥的 base64 编码**；
//   3) base64 解码还原主密钥（严格解码失败则按明文兜底，兼容旧产物）；
//   4) 读不到则退镜像常量（base64 串逐字节 ^0x3C 藏匿，防 strings 直读）。
//
// 逆向对象仍是 app/libs/arm64-v8a/libflutter.so（BoringSSL）与 libapp.so（Dart AOT 快照）。

#ifndef KL40B_HOST_TEST
#include <jni.h>
#endif

#include "mt_rng.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>

#ifndef KL40B_HOST_TEST
#include <unistd.h>
#endif

#ifdef ANDROID
#include <android/log.h>
#define LOG_TAG "kl40b"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) printf(__VA_ARGS__)
#endif

// ============================================================
// MD5（RFC 1321）—— 用于签名 sign = md5(enc + KEY)
// ============================================================
namespace tally_ns {

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
    for (int i = 0; i < 16; i++) {
        M[i] = (uint32_t)p[i * 4] | ((uint32_t)p[i * 4 + 1] << 8) |
               ((uint32_t)p[i * 4 + 2] << 16) | ((uint32_t)p[i * 4 + 3] << 24);
    }
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

static std::string hex(const uint8_t* d, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) { s += H[d[i] >> 4]; s += H[d[i] & 0xF]; }
    return s;
}

static std::string digest(const std::string& in) {
    Ctx x;
    update(x, reinterpret_cast<const uint8_t*>(in.data()), in.size());
    uint64_t bits = x.len * 8;
    uint8_t pad = 0x80;
    update(x, &pad, 1);
    uint8_t zero = 0x00;
    while (x.buflen != 56) update(x, &zero, 1);
    uint8_t lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (uint8_t)((bits >> (8 * i)) & 0xFF);
    update(x, lb, 8);
    uint8_t out[16];
    uint32_t w[4] = {x.a, x.b, x.c, x.d};
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) out[i * 4 + j] = (uint8_t)((w[i] >> (8 * j)) & 0xFF);
    return hex(out, 16);
}

} // namespace tally_ns

// ============================================================
// SHA-256（RC4 主钥派生 + nativeAnswer 共用）
// ============================================================
namespace omega_ns {
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

static void finish(Ctx& c, uint8_t out[32]) {
    uint64_t bits = c.bitlen + c.datalen * 8;
    c.data[c.datalen++] = 0x80;
    if (c.datalen > 56) { while (c.datalen < 64) c.data[c.datalen++] = 0; transform(c, c.data); c.datalen = 0; }
    while (c.datalen < 56) c.data[c.datalen++] = 0;
    for (int i = 7; i >= 0; i--) c.data[c.datalen++] = (uint8_t)((bits >> (i*8)) & 0xFF);
    transform(c, c.data);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)((c.h[i] >> 24) & 0xFF);
        out[i*4+1] = (uint8_t)((c.h[i] >> 16) & 0xFF);
        out[i*4+2] = (uint8_t)((c.h[i] >>  8) & 0xFF);
        out[i*4+3] = (uint8_t)( c.h[i]        & 0xFF);
    }
}

static std::string hex_of(const uint8_t* d, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) { s += H[d[i] >> 4]; s += H[d[i] & 0xF]; }
    return s;
}

static std::string digest_hex(const std::string& s) {
    Ctx c; update(c, reinterpret_cast<const uint8_t*>(s.data()), s.size());
    uint8_t out[32]; finish(c, out); return hex_of(out, 32);
}

// 32 字节原始摘要（RC4 主钥）
static std::string digest_raw(const std::string& s) {
    Ctx c; update(c, reinterpret_cast<const uint8_t*>(s.data()), s.size());
    uint8_t out[32]; finish(c, out);
    return std::string(reinterpret_cast<const char*>(out), 32);
}
} // namespace omega_ns

// ============================================================
// RC4（流密码，请求体加密）
// ============================================================
namespace sigil_ns {

static std::string rc4_hex(const std::string& key, const std::string& data) {
    uint8_t S[256];
    for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;
    int klen = (int)key.size();
    if (klen == 0) klen = 1;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + (uint8_t)key[i % klen]) & 0xFF;
        uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
    }
    int x = 0, y = 0;
    std::string out; out.reserve(data.size() * 2);
    static const char* H = "0123456789abcdef";
    for (size_t n = 0; n < data.size(); n++) {
        x = (x + 1) & 0xFF;
        y = (y + S[x]) & 0xFF;
        uint8_t t = S[x]; S[x] = S[y]; S[y] = t;
        uint8_t k = S[(S[x] + S[y]) & 0xFF];
        uint8_t c = (uint8_t)data[n] ^ k;
        out += H[c >> 4]; out += H[c & 0xF];
    }
    return out;
}

} // namespace sigil_ns

// ============================================================
// base64（密钥承载编码）：严格解码，拒绝非字母表字符/错长/错位填充
// ============================================================
namespace b64_ns {

static int val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// 严格：长度须为 4 的倍数；'=' 仅允许出现在末组末两位；表外字符一律判失败。
static bool decode(const std::string& in, std::string& out) {
    out.clear();
    if (in.empty() || in.size() % 4 != 0) return false;
    out.reserve(in.size() / 4 * 3);
    for (size_t i = 0; i < in.size(); i += 4) {
        int v[4]; int pad = 0;
        for (int k = 0; k < 4; k++) {
            char c = in[i + k];
            if (c == '=') {
                if (k < 2) return false;
                pad++; v[k] = 0;
            } else {
                if (pad > 0) return false;
                v[k] = val(c);
                if (v[k] < 0) return false;
            }
        }
        if (pad > 0 && i + 4 != in.size()) return false;
        uint32_t n = ((uint32_t)v[0] << 18) | ((uint32_t)v[1] << 12) |
                     ((uint32_t)v[2] << 6) | (uint32_t)v[3];
        out += (char)((n >> 16) & 0xFF);
        if (pad < 2) out += (char)((n >> 8) & 0xFF);
        if (pad < 1) out += (char)(n & 0xFF);
    }
    return !out.empty();
}

// 仅测试用：编码（与解码互逆）
[[maybe_unused]] static std::string encode(const std::string& in) {
    static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string o; o.reserve((in.size() + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 3 <= in.size(); i += 3) {
        uint32_t n = ((uint32_t)(uint8_t)in[i] << 16) | ((uint32_t)(uint8_t)in[i+1] << 8) | (uint8_t)in[i+2];
        o += T[(n >> 18) & 63]; o += T[(n >> 12) & 63]; o += T[(n >> 6) & 63]; o += T[n & 63];
    }
    size_t rem = in.size() - i;
    if (rem == 1) {
        uint32_t n = (uint32_t)(uint8_t)in[i] << 16;
        o += T[(n >> 18) & 63]; o += T[(n >> 12) & 63]; o += '='; o += '=';
    } else if (rem == 2) {
        uint32_t n = ((uint32_t)(uint8_t)in[i] << 16) | ((uint32_t)(uint8_t)in[i+1] << 8);
        o += T[(n >> 18) & 63]; o += T[(n >> 12) & 63]; o += T[(n >> 6) & 63]; o += '=';
    }
    return o;
}

} // namespace b64_ns

// ============================================================
// 密钥：优先从真实 libapp.so 对象池取；失败退镜像常量
// ============================================================
namespace anchor_store {

// 镜像兜底：主密钥的 **base64 串** 逐字节 ^0x3C（volatile 防常量折叠，rule 35）。
// 本数组按 ^0x3C 还原后 = "RmF0ZG9nX3ByaXNt"（base64 承载，运行时 b64decode 还原主密钥）。
static const volatile uint8_t MIRROR[] = {
    110,81,122,12,102,123,5,82,100,15,126,69,93,100,114,72
};

static const char TAG[] = "FDK4B|";
static const size_t TAG_LEN = sizeof(TAG) - 1;

static std::string g_anchor;
static bool g_ready = false;
static bool g_from_payload = false;

static bool locate_payload(std::string& path) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[1024];
    std::string dir;
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, "libprism.so")) continue;
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

static const std::string& get() {
    if (g_ready) return g_anchor;
    std::string path, carried;
    bool from_payload = false;
    if (locate_payload(path) && read_tag_from_payload(path, carried)) {
        from_payload = true;
    } else {
        std::string m;
        m.reserve(sizeof(MIRROR));
        for (size_t i = 0; i < sizeof(MIRROR); i++) m += (char)(MIRROR[i] ^ 0x3C);
        carried = m;
    }
    // 密钥以 base64 承载；严格解码失败则按明文兜底（兼容未重建的旧载荷）。
    std::string key;
    if (!b64_ns::decode(carried, key)) key = carried;
    g_anchor = key;
    g_from_payload = from_payload;
    LOGI("KL40b key: source=%s", from_payload ? "primary" : "fallback");
    g_ready = true;
    return g_anchor;
}

[[maybe_unused]] static bool from_payload() { get(); return g_from_payload; }

} // namespace anchor_store

// ============================================================
// 引擎校验桩（模拟 BoringSSL 的证书链校验位置）
//   —— static、**不导出符号**；调用点只在 native 内部，Java/钩子够不着。
//   —— 原始实现恒判"不可信"（返回 0）；须 patch 成恒真才能取到真数据。
// ============================================================
namespace engine_gate {

// 内置链指纹（volatile 防常量折叠：输入取自运行时，编译器无法证明比较结果）
static volatile uint32_t g_chain_pin = 0x7F3A9C15u;

#ifdef KL40B_HOST_TEST
static int g_override = -1;   // 仅宿主自测：-1 真实实现 / 0 强制不可信 / 1 强制可信
#endif

static int verify_chain(const uint8_t* chain, size_t len) {
    uint32_t acc = 0xA5A5A5A5u;
    for (size_t i = 0; i < len; i++) {
        acc = (acc ^ (uint32_t)chain[i]) * 16777619u;   // FNV 步进
        acc ^= (acc >> 13);
    }
    if (acc == g_chain_pin) return 1;    // 链指纹命中内置 pin 才判可信
    return 0;                            // 训练环境自签 → 恒不可信
}

// 只读：引擎是否已放行（未 patch → 0）
static bool passed() {
#ifdef KL40B_HOST_TEST
    if (g_override >= 0) return g_override == 1;
#endif
    static uint8_t probe[48];
#ifdef KL40B_HOST_TEST
    for (int i = 0; i < 48; i++) probe[i] = (uint8_t)(0x10 + i);
#else
    static bool inited = false;
    if (!inited) {
        uint64_t mix = (uint64_t)time(nullptr) * 2654435761ULL ^ ((uint64_t)getpid() << 19);
        for (int i = 0; i < 48; i++) {
            mix = mix * 6364136223846793005ULL + 1442695040888963407ULL;
            probe[i] = (uint8_t)(mix >> 33);
        }
        inited = true;
    }
#endif
    return verify_chain(probe, sizeof(probe)) == 1;
}

} // namespace engine_gate

// ============================================================
// 加密 + 签名（引擎未放行 → 静默投毒）
// ============================================================

static std::string taint(const std::string& m) {
    std::string o = m;
    uint32_t p = 0x9E3779B9u;
    for (size_t i = 0; i < o.size(); i++) {
        p = p * 1664525u + 1013904223u;
        o[i] = (char)((uint8_t)o[i] ^ 0x5A ^ (uint8_t)(p >> 24));
    }
    return o;
}

static std::string active_master() {
    std::string m = anchor_store::get();
    if (!engine_gate::passed()) return taint(m);   // 静默投毒：enc/sign 全错，服务端不认
    return m;
}

#ifdef KL40B_HOST_TEST
// 宿主对拍用：直接以给定主钥计算（不经过引擎判定）
static std::string enc_with(const std::string& master, int page, long long ts) {
    char head[64];
    snprintf(head, sizeof(head), "page=%d&ts=%lld", page, ts);
    std::string kst = omega_ns::digest_raw(master + "|rc4");
    return sigil_ns::rc4_hex(kst, std::string(head));
}
static std::string sign_with(const std::string& master, const std::string& enc) {
    return tally_ns::digest(enc + master);
}
#endif

[[maybe_unused]] static std::string build_enc(int page, long long ts) {
    char head[64];
    snprintf(head, sizeof(head), "page=%d&ts=%lld", page, ts);
    const std::string master = active_master();
    std::string kst = omega_ns::digest_raw(master + "|rc4");
    return sigil_ns::rc4_hex(kst, std::string(head));
}

[[maybe_unused]] static std::string build_sign(int page, long long ts, const std::string& enc) {
    (void)page; (void)ts;
    const std::string master = active_master();
    return tally_ns::digest(enc + master);
}

// nativeAnswer：sha256(str(1000 数和))[:8]，SEED_KL40B = 20281001
static std::string build_answer() {
    return omega_ns::digest_hex(std::to_string(mt_rng::kl_server_sum(20281001))).substr(0, 8);
}

// ============================================================
// 宿主自测
// ============================================================
#ifdef KL40B_HOST_TEST

int main() {
    printf("md5(abc)          = %s\n", tally_ns::digest("abc").c_str());
    printf("expect            = 900150983cd24fb0d6963f7d28e17f72\n");
    printf("sha256(abc)       = %s\n", omega_ns::digest_hex("abc").c_str());
    printf("expect            = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n");
    // RC4 教科书向量：key="Key", pt="Plaintext" → BBF316E8D940AF0AD3
    printf("rc4(Key,Plaintext)= %s\n", sigil_ns::rc4_hex("Key", "Plaintext").c_str());
    printf("expect            = bbf316e8d940af0ad3\n");
    {
        std::string dec, bad;
        bool ok = b64_ns::decode("RmF0ZG9nX3ByaXNt", dec);
        printf("b64(RmF0..)       = %s ok=%d (expect Fatdog_prism / 1)\n", dec.c_str(), (int)ok);
        printf("b64(plain)        = ok=%d (expect 0)\n", (int)b64_ns::decode("Fatdog_prism", bad));
        printf("b64 roundtrip     = %d (expect 1)\n",
               (int)(b64_ns::encode(dec) == "RmF0ZG9nX3ByaXNt"));
    }

    const std::string M = "Fatdog_prism";
    std::string e1 = enc_with(M, 1, 1787013761LL);
    std::string s1 = sign_with(M, e1);
    std::string e2 = enc_with(M, 7, 1700000000LL);
    std::string s2 = sign_with(M, e2);
    printf("enc(1,1787013761) = %s\n", e1.c_str());
    printf("sign(1,1787013761)= %s\n", s1.c_str());
    printf("enc(7,1700000000) = %s\n", e2.c_str());
    printf("sign(7,1700000000)= %s\n", s2.c_str());

    printf("answer(KL40b)     = %s\n", build_answer().c_str());
    printf("master(raw)       = %s (from %s)\n", anchor_store::get().c_str(),
           anchor_store::from_payload() ? "payload" : "mirror");

    // 引擎校验：未放行 → 投毒；模拟 patch 后 → 用真钥
    printf("engine.passed     = %d (expect 0)\n", (int)engine_gate::passed());
    std::string poisoned = active_master();
    printf("active(tampered)  = %s (expect != Fatdog_prism)\n", poisoned.c_str());
    engine_gate::g_override = 1;
    printf("after-passed      = %d (expect 1)\n", (int)engine_gate::passed());
    std::string clean = active_master();
    printf("active(patched)   = %s (expect Fatdog_prism)\n", clean.c_str());
    return 0;
}

#else  // ---------- JNI ----------

extern "C" {

// 加密：enc = hex(RC4(SHA256("<KEY>|rc4"), "page=N&ts=T"))
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterPrism_nativeEnc(JNIEnv* env, jclass clz, jint page, jlong ts) {
    (void)clz;
    return env->NewStringUTF(build_enc((int)page, (long long)ts).c_str());
}

// 签名：sign = md5(enc + "<KEY>")
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterPrism_nativeSign(JNIEnv* env, jclass clz, jint page, jlong ts,
                                                jstring encStr) {
    (void)clz;
    const char* c = encStr ? env->GetStringUTFChars(encStr, nullptr) : "";
    std::string enc(c ? c : "");
    if (encStr && c) env->ReleaseStringUTFChars(encStr, c);
    return env->NewStringUTF(build_sign((int)page, (long long)ts, enc).c_str());
}

// 只读展示：引擎校验是否已放行（中性，不点破手段、不判胜）
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterPrism_nativeGetProbe(JNIEnv* env, jclass clz) {
    (void)clz;
    return env->NewStringUTF(engine_gate::passed() ? "引擎校验：通过" : "引擎校验：未通过");
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterPrism_nativeAnswer(JNIEnv* env, jclass clz) {
    (void)clz;
    return env->NewStringUTF(build_answer().c_str());
}

// 只读自检：仅报告实现是否完好（不报算法/密钥/载荷来源、不判胜）
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterPrism_nativeGetStatus(JNIEnv* env, jclass clz) {
    (void)clz;
    const bool ok = (tally_ns::digest("abc") == "900150983cd24fb0d6963f7d28e17f72"
                     && sigil_ns::rc4_hex("Key", "Plaintext") == "bbf316e8d940af0ad3");
    return env->NewStringUTF(ok ? "自检:通过" : "自检:异常");
}

} // extern "C"

#endif
