// kl36.cpp —— KL36「云中锦书」（碧落天 · Flutter/Dart 逆向入门）
//
// 伴生 so（runtime 签名侧）：宿主 App 不是 Flutter 运行时，无法执行 libapp.so，
// 因此由本 so 承担"发包瞬间的签名"。**密钥以真实 Flutter 载荷 libapp.so 的对象池为准**：
//   1) 运行时按 /proc/self/maps 定位自身所在目录，读同目录的 libapp.so；
//   2) 在其中搜哨兵 "FDK36|"，取到下一个 '|' 之间的字符串作为签名密钥；
//   3) 若读不到（未抽取/被裁掉），退回镜像常量（异或藏匿，防 strings 直读）。
// 本关只用 **MD5** 一个原语：sign = md5("page=<page>&ts=<ts>&k=<KEY>")。
//
// 逆向对象是 app/libs/arm64-v8a/libapp.so（Dart AOT 快照）——玩家用 Blutter 解对象池拿密钥。
// 本文件不参与"出题"的答案计算，只做签名与取数。

#ifndef KL36_HOST_TEST
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
#define LOG_TAG "kl36"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) printf(__VA_ARGS__)
#endif

// ============================================================
// MD5（RFC 1321）—— 本关唯一摘要原语
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
    uint64_t len = 0;          // 已处理字节数
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
        if (i < 16)      { F = (B & C) | (~B & D);         g = i; }
        else if (i < 32) { F = (D & B) | (~D & C);         g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D;                  g = (3 * i + 5) % 16; }
        else             { F = C ^ (B | ~D);               g = (7 * i) % 16; }
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

} // namespace md5_ns

// ============================================================
// SHA-256（仅用于 nativeAnswer：sha256(str(sum))[:8]）
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
    uint32_t h[8];
    uint64_t bitlen;
    uint8_t data[64];
    size_t datalen;
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

static std::string final_hex(Ctx& c) {
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

static std::string digest_hex(const std::string& s) {
    Ctx c;
    update(c, reinterpret_cast<const uint8_t*>(s.data()), s.size());
    return final_hex(c);
}
} // namespace sha256_ns

// ============================================================
// 密钥：优先从真实 libapp.so 对象池取；失败退镜像常量
// ============================================================
namespace key_store {

// 镜像兜底常量：真标记的 UTF-8 各字节 ^ 0x3C（volatile 防常量折叠，rule 35）
static const volatile uint8_t MIRROR[] = {
    70^0x3C, 97^0x3C, 116^0x3C, 100^0x3C, 111^0x3C, 103^0x3C, 95^0x3C,
    115^0x3C, 99^0x3C, 114^0x3C, 111^0x3C, 108^0x3C, 108^0x3C
};

static const char TAG[] = "FDK36|";   // 对象池哨兵（只有前缀，密钥不在本文件）
static const size_t TAG_LEN = sizeof(TAG) - 1;

static std::string g_key;
static bool g_ready = false;
static bool g_from_payload = false;

// 由 /proc/self/maps 中自身 so 的路径推出同目录的 libapp.so
static bool locate_payload(std::string& path) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[1024];
    std::string dir;
    while (fgets(line, sizeof(line), fp)) {
        const char* p = strstr(line, "libflutterbridge.so");
        if (!p) continue;
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

// 在 libapp.so 中搜哨兵，返回其后的第一段字符串
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
    if (g_ready) return g_key;
    std::string path, key;
    if (locate_payload(path) && read_tag_from_payload(path, key)) {
        g_key = key;
        g_from_payload = true;
        LOGI("KL36 key taken from Flutter payload object pool");
    } else {
        std::string m;
        m.reserve(sizeof(MIRROR));
        for (size_t i = 0; i < sizeof(MIRROR); i++) m += (char)(MIRROR[i] ^ 0x3C);
        g_key = m;
        g_from_payload = false;
        LOGI("KL36 payload unavailable, using mirror key");
    }
    g_ready = true;
    return g_key;
}

static bool from_payload() { get(); return g_from_payload; }

} // namespace key_store

// ============================================================
// 签名：sign = md5("page=<page>&ts=<ts>&k=<KEY>")
// ============================================================
static std::string build_sign(int page, long long ts) {
    const std::string& k = key_store::get();
    char head[64];
    snprintf(head, sizeof(head), "page=%d&ts=%lld&k=", page, ts);
    return md5_ns::digest(std::string(head) + k);
}

// nativeAnswer：sha256(str(1000 数和))[:8]（与其它网络关一致；和由 SEED 现场复算）
static std::string build_answer() {
    std::string s = std::to_string(mt_rng::kl_server_sum(20271125));
    return sha256_ns::digest_hex(s).substr(0, 8);
}

// ============================================================
// 宿主自测（-DKL36_HOST_TEST）
// ============================================================
#ifdef KL36_HOST_TEST

int main() {
    printf("md5(abc)        = %s\n", md5_ns::digest("abc").c_str());
    printf("expect          = 900150983cd24fb0d6963f7d28e17f72\n");
    printf("sign(1,1787013761) = %s\n", build_sign(1, 1787013761LL).c_str());
    printf("expect             = 7299ee3ec8e2da29f775da0094ad2044\n");
    printf("sign(7,1700000000) = %s\n", build_sign(7, 1700000000LL).c_str());
    printf("expect             = 9e96f422a0a940e288c1da4d7a7b8658\n");
    printf("answer(KL36)    = %s\n", build_answer().c_str());
    printf("expect          = f13984c0\n");
    printf("key source      = %s\n", key_store::from_payload() ? "payload" : "mirror");
    return 0;
}

#else  // ---------- JNI（真机路径） ----------

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterBridge_nativeSign(JNIEnv* env, jclass clz, jint page, jlong ts) {
    (void)clz;
    return env->NewStringUTF(build_sign((int)page, (long long)ts).c_str());
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterBridge_nativeAnswer(JNIEnv* env, jclass clz) {
    (void)clz;
    return env->NewStringUTF(build_answer().c_str());
}

// 只读自检：只报告密钥来源与 MD5 自检，不含密钥明文、不判胜
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterBridge_nativeGetStatus(JNIEnv* env, jclass clz) {
    (void)clz;
    const bool ok = (md5_ns::digest("abc") == "900150983cd24fb0d6963f7d28e17f72");
    char buf[160];
    snprintf(buf, sizeof(buf), "摘要自检:%s 载荷:%s 镜像:%s",
             ok ? "通过" : "异常",
             key_store::from_payload() ? "命中" : "未命中",
             key_store::from_payload() ? "未用" : "已用");
    return env->NewStringUTF(buf);
}

} // extern "C"

#endif
