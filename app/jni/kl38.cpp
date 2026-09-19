// kl38.cpp —— KL38「雾里观花」（碧落天 · Flutter/BoringSSL 证书固定绕过）
//
// 伴生 so（runtime 侧）。宿主 App 不是 Flutter 运行时，无法执行 libapp.so，
// 因此由本 so 承担"发包瞬间的加密 + 签名 + 证书固定校验"。
//
// 本关算法（摘要 + 对称，**无 HMAC**）：
//   aeskey = SHA256("<KEY>|aes") 的前 16 字节
//   enc    = AES-128-CBC-PKCS7(aeskey, iv=随机 16B 前置, "page=<page>&ts=<ts>")  → hex
//   sign   = SHA256(enc_hex + "<KEY>") 的十六进制前 16 位
//
// 证书固定（本关的题眼）：服务器用自签 CA，App 侧在 TLS 握手后拿叶子证书 DER
// 再算一次 SHA-256，与硬编码 pin 比对；不一致即抛错 → **请求根本发不出去**。
// 玩家必须先绕过这一层（hook / patch BoringSSL 的 verify_cert_chain）才拿得到数据。
//
// 密钥以真实 Flutter 载荷 libapp.so 的对象池为准（同 KL36 的口径）：
//   1) 按 /proc/self/maps 定位自身所在目录，读同目录的 libapp.so；
//   2) 搜哨兵 "FDK38|"，取到下一个 '|' 之间的字符串作为主密钥；
//   3) 读不到则退镜像常量（逐字节 ^0x3C 藏匿，防 strings 直读）。
//
// 逆向对象仍是 app/libs/arm64-v8a/libapp.so（Dart AOT 快照）。

#ifndef KL38_HOST_TEST
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

#ifndef KL38_HOST_TEST
#include <unistd.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifdef ANDROID
#include <android/log.h>
#define LOG_TAG "kl38"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) printf(__VA_ARGS__)
#endif

// ============================================================
// SHA-256（证书指纹 + sign + answer 共用）
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

static std::string digest_hex_bytes(const uint8_t* p, size_t n) {
    Ctx c; update(c, p, n);
    uint8_t out[32]; finish(c, out); return hex_of(out, 32);
}

// 取摘要的前 16 字节（RAW），用作 AES-128 密钥
static std::string digest_first16(const std::string& s) {
    Ctx c; update(c, reinterpret_cast<const uint8_t*>(s.data()), s.size());
    uint8_t out[32]; finish(c, out);
    return std::string(reinterpret_cast<const char*>(out), 16);
}
} // namespace sha256_ns

// ============================================================
// AES-128（加密，CBC 模式 + PKCS#7）
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

// CBC + PKCS#7，输出 hex(IV || CT)
static std::string cbcEncryptHex(const std::string& key16, const uint8_t iv[16], const std::string& plain) {
    uint8_t k[16];
    memset(k, 0, 16);
    size_t kn = key16.size() < 16 ? key16.size() : 16;
    memcpy(k, key16.data(), kn);
    Ctx ctx;
    ctx.expand(k);

    std::string buf = plain;
    uint8_t pad = (uint8_t)(16 - (buf.size() % 16));
    buf.append(pad, (char)pad);

    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve((buf.size() + 16) * 2);
    for (int i = 0; i < 16; i++) { out += H[iv[i] >> 4]; out += H[iv[i] & 0xF]; }

    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < buf.size(); off += 16) {
        uint8_t x[16], blk[16];
        for (int i = 0; i < 16; i++) x[i] = (uint8_t)buf[off + i] ^ prev[i];
        ctx.encryptBlock(x, blk);
        memcpy(prev, blk, 16);
        for (int i = 0; i < 16; i++) { out += H[blk[i] >> 4]; out += H[blk[i] & 0xF]; }
    }
    return out;
}

} // namespace aes_ns

// ============================================================
// 密钥：优先从真实 libapp.so 对象池取；失败退镜像常量
// ============================================================
namespace key_store {

// 镜像兜底：真标记 UTF-8 各字节 ^0x3C（volatile 防常量折叠，rule 35）
static const volatile uint8_t MIRROR[] = {
    122,93,72,88,83,91,99,84,93,70,89
};

static const char TAG[] = "FDK38|";
static const size_t TAG_LEN = sizeof(TAG) - 1;

static std::string g_key;
static bool g_ready = false;
static bool g_from_payload = false;

static bool locate_payload(std::string& path) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[1024];
    std::string dir;
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, "libflutternet.so")) continue;
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
    if (g_ready) return g_key;
    std::string path, key;
    if (locate_payload(path) && read_tag_from_payload(path, key)) {
        g_key = key;
        g_from_payload = true;
        LOGI("KL38 key taken from Flutter payload object pool");
    } else {
        std::string m;
        m.reserve(sizeof(MIRROR));
        for (size_t i = 0; i < sizeof(MIRROR); i++) m += (char)(MIRROR[i] ^ 0x3C);
        g_key = m;
        g_from_payload = false;
        LOGI("KL38 payload unavailable, using mirror key");
    }
    g_ready = true;
    return g_key;
}

static bool from_payload() { get(); return g_from_payload; }

// 诱饵主密钥（仅用于"被检出"时静默投毒，服务端会回 403）
static std::string decoy_master() {
    static const volatile uint8_t D[] = {122,93,72,88,83,91,99,90,83,91};
    std::string s;
    for (size_t i = 0; i < sizeof(D); i++) s += (char)(D[i] ^ 0x3C);
    return s;
}

} // namespace key_store

// ============================================================
// 证书固定（pin）：叶子证书 DER 的 SHA-256
// ============================================================
namespace pin_store {

// 线上叶子证书的 SHA-256 指纹（32 字节 hex，逐字节 ^0x3C 藏匿）。
// 注意：这里锁的是**线上证书**——本地训练环境是自签 CA，指纹必然对不上，
// 所以 App 的 HTTPS 请求会被自己拒掉，必须先绕过这一层。
static const volatile uint8_t PIN_XOR[] = {
    11,5,4,9,89,15,15,14,13,95,88,13,9,14,95,89,90,94,90,89,89,13,12,14,8,93,93,90,9,13,12,10,
    95,11,8,5,14,93,13,10,95,15,90,4,88,5,14,10,12,93,88,15,89,95,5,11,14,88,90,4,8,4,95,4
};

static std::string pin_hex() {
    std::string s;
    s.reserve(sizeof(PIN_XOR));
    for (size_t i = 0; i < sizeof(PIN_XOR); i++) s += (char)(PIN_XOR[i] ^ 0x3C);
    return s;
}

static bool verify(const uint8_t* der, size_t len) {
    if (!der || len == 0) return false;
    return sha256_ns::digest_hex_bytes(der, len) == pin_hex();
}
} // namespace pin_store

// ============================================================
// 反调试：评分制（>=2 才判定，防单点误报 —— KL19/KL28 教训）
// ============================================================
namespace guard {
static const int THRESHOLD = 2;
static int g_score = -1;

static int score_ptrace() {
#ifdef __linux__
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            long pid = strtol(line + 10, nullptr, 10);
            fclose(f);
            return pid != 0 ? 1 : 0;   // 只认"真实非零 tracer"
        }
    }
    fclose(f);
#endif
    return 0;
}

static int score_maps() {
#ifdef __linux__
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "frida") || strstr(line, "gadget") ||
            strstr(line, "gum-js") || strstr(line, "linjector")) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
#endif
    return 0;
}

static int score_port() {
#ifdef __linux__
    for (int port = 27042; port <= 27044; port++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)port);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        int r = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
        close(fd);
        if (r == 0) return 1;
    }
#endif
    return 0;
}

static int score_threads() {
#ifdef __linux__
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", getpid());
    DIR* d = opendir(path);
    if (!d) return 0;
    struct dirent* de;
    int hit = 0;
    while ((de = readdir(d)) != nullptr) {
        if (de->d_name[0] == '.') continue;
        char cp[128];
        snprintf(cp, sizeof(cp), "/proc/%d/task/%s/comm", getpid(), de->d_name);
        FILE* f = fopen(cp, "r");
        if (!f) continue;
        char name[64];
        if (fgets(name, sizeof(name), f)) {
            // 只认 frida 专属线程名（gmain/gdbus 等 GLib 通用名不计，防误报）
            if (strstr(name, "gum-js-loop") || strstr(name, "pool-frida") ||
                strstr(name, "linjector")) { hit = 1; }
        }
        fclose(f);
        if (hit) break;
    }
    closedir(d);
    return hit;
#else
    return 0;
#endif
}

static int compute() {
    if (g_score >= 0) return g_score;
    int s = score_ptrace() + score_maps() + score_port() + score_threads();
    g_score = s;
    if (s >= THRESHOLD) LOGI("KL38 guard tripped (score=%d)", s);
    return s;
}

static bool tripped() { return compute() >= THRESHOLD; }
} // namespace guard

// ============================================================
// 加密 + 签名
// ============================================================

static void make_iv(uint8_t iv[16]) {
#ifdef KL38_HOST_TEST
    for (int i = 0; i < 16; i++) iv[i] = (uint8_t)i;   // 自测固定 IV
#else
    static uint32_t seq = 0;
    seq++;
    uint64_t mix = (uint64_t)time(nullptr) * 1000003ULL
                 ^ ((uint64_t)getpid() << 32)
                 ^ (uint64_t)seq;
    for (int i = 0; i < 16; i++) {
        mix = mix * 6364136223846793005ULL + 1442695040888963407ULL;
        iv[i] = (uint8_t)(mix >> 33);
    }
#endif
}

// 当前使用的主密钥：被检出时改用诱饵钥（静默投毒）
static std::string active_master() {
    return guard::tripped() ? key_store::decoy_master() : key_store::get();
}

static std::string build_enc(int page, long long ts) {
    char head[64];
    snprintf(head, sizeof(head), "page=%d&ts=%lld", page, ts);
    const std::string& master = active_master();
    std::string aeskey = sha256_ns::digest_first16(master + "|aes");
    uint8_t iv[16];
    make_iv(iv);
    return aes_ns::cbcEncryptHex(aeskey, iv, std::string(head));
}

static std::string build_sign(int page, long long ts, const std::string& enc) {
    (void)page; (void)ts;
    const std::string& master = active_master();
    return sha256_ns::digest_hex(enc + master).substr(0, 16);
}

// nativeAnswer：sha256(str(1000 数和))[:8]，SEED_KL38 = 20280701
static std::string build_answer() {
    return sha256_ns::digest_hex(std::to_string(mt_rng::kl_server_sum(20280701))).substr(0, 8);
}

// ============================================================
// 宿主自测
// ============================================================
#ifdef KL38_HOST_TEST

int main() {
    printf("sha256(abc)       = %s\n", sha256_ns::digest_hex("abc").c_str());
    printf("expect            = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n");
    std::string e1 = build_enc(1, 1787013761LL);
    std::string e2 = build_enc(7, 1700000000LL);
    printf("enc(1,1787013761) = %s\n", e1.c_str());
    printf("expect            = 000102030405060708090a0b0c0d0e0f7d4dbd188ea323504608cb166b18fad84f00fb5f1c2b0d2fd8c6561bcf0b2366\n");
    printf("sign(1,1787013761)= %s\n", build_sign(1, 1787013761LL, e1).c_str());
    printf("expect            = 50dd0bc6a11aef2e\n");
    printf("enc(7,1700000000) = %s\n", e2.c_str());
    printf("expect            = 000102030405060708090a0b0c0d0e0f45d8692b9d51b0d750852f46481ece6d90c61f05a30574a487c3447529a1b83a\n");
    printf("sign(7,1700000000)= %s\n", build_sign(7, 1700000000LL, e2).c_str());
    printf("expect            = da19ec6a90056b64\n");
    printf("answer(KL38)      = %s\n", build_answer().c_str());
    printf("expect            = 5c8a0ad4\n");
    printf("master            = %s (from %s)\n", key_store::get().c_str(),
           key_store::from_payload() ? "payload" : "mirror");
    printf("guard score       = %d (tripped=%d)\n", guard::compute(), (int)guard::tripped());
    // 证书固定对拍：pin 对应的明文 → true；任意其它 DER → false
    {
        const char* prod = "fatdog://prod/leaf/2026";
        printf("pin(prod)         = %d (expect 1)\n",
               (int)pin_store::verify(reinterpret_cast<const uint8_t*>(prod), strlen(prod)));
        printf("pin(local self)   = %d (expect 0)\n",
               (int)pin_store::verify(reinterpret_cast<const uint8_t*>("self-signed-cert"), 16));
        printf("pin hex           = %s\n", pin_store::pin_hex().c_str());
    }
    return 0;
}

#else  // ---------- JNI ----------

extern "C" {

// 加密：enc = AES-128-CBC-PKCS7(SHA256("<KEY>|aes")[:16], iv||ct)
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterNet_nativeEnc(JNIEnv* env, jclass clz, jint page, jlong ts) {
    (void)clz;
    return env->NewStringUTF(build_enc((int)page, (long long)ts).c_str());
}

// 签名：sign = SHA256(enc + "<KEY>")[:16]
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterNet_nativeSign(JNIEnv* env, jclass clz, jint page, jlong ts,
                                              jstring encStr) {
    (void)clz;
    const char* c = encStr ? env->GetStringUTFChars(encStr, nullptr) : "";
    std::string enc(c ? c : "");
    if (encStr && c) env->ReleaseStringUTFChars(encStr, c);
    return env->NewStringUTF(build_sign((int)page, (long long)ts, enc).c_str());
}

// 证书固定校验：sha256(叶子证书 DER) 是否等于内置 pin
JNIEXPORT jboolean JNICALL
Java_com_fatdog_reverse_FlutterNet_nativeCheckPin(JNIEnv* env, jclass clz, jbyteArray der) {
    (void)clz;
    if (!der) return JNI_FALSE;
    jsize n = env->GetArrayLength(der);
    if (n <= 0) return JNI_FALSE;
    std::vector<uint8_t> buf((size_t)n);
    env->GetByteArrayRegion(der, 0, n, reinterpret_cast<jbyte*>(buf.data()));
    return pin_store::verify(buf.data(), buf.size()) ? JNI_TRUE : JNI_FALSE;
}

// 展示用：返回 pin 前缀（公开信息，非密钥）
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterNet_nativeGetPin(JNIEnv* env, jclass clz) {
    (void)clz;
    return env->NewStringUTF(pin_store::pin_hex().substr(0, 16).c_str());
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterNet_nativeAnswer(JNIEnv* env, jclass clz) {
    (void)clz;
    return env->NewStringUTF(build_answer().c_str());
}

// 只读自检：只报算法口径、证书固定与检测评分，不含密钥明文、不判胜
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterNet_nativeGetStatus(JNIEnv* env, jclass clz) {
    (void)clz;
    int score = guard::compute();
    char buf[220];
    snprintf(buf, sizeof(buf),
             "密码原语:AES-128-CBC + SHA-256 | 证书固定:SHA-256 pin | 载荷:%s | 检测评分:%d/%d",
             key_store::from_payload() ? "命中" : "镜像兜底",
             score, guard::THRESHOLD);
    return env->NewStringUTF(buf);
}

} // extern "C"

#endif
