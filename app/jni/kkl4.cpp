/*
 * 太玄之初 KKL4：锁妖塔——代码段 CRC 自校验 + 三点记账守卫（教学版）。
 *
 * libkkl4.so 不直接判胜：玩家每次翻页取数都要先过 nativeSign()。
 *  ① nativeOpen   : 开门时校验 CRC 并建立记账状态
 *  ② nativeSign   : 每次取数前再校验 CRC + 核账，通过才签下一页
 *  ③ nativeCommit : Java 收到一页后回调 native 记账，三点交叉核账
 *
 * CRC 基线由 tools/gen_kkl4_crc_baseline.py 在 NDK 产物上按 ABI 烘焙，
 * 常量放在独立翻译单元 kkl4_baseline.c，校验窗口覆盖 open/sign/commit/
 * 校验器自身四组导出符号。patch 任一窗口内指令或 inline hook 都会让
 * 后续签名密钥被永久投毒，服务端 /api/kkl4 静默 403。
 */
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <time.h>
#include <unistd.h>

/* ================= 真标记：UTF-16 藏匿 ================= */
static const volatile jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F, 0x0067, 0x0072, 0x0069, 0x0074
};
#define MARKER_LEN (sizeof(MARKER) / sizeof(jchar))

/* 明文诱饵：strings 可直接看到一字之差 */
static const char DECOY[] = "Fatdog_grim";

static const char SALT[] = "|kkl4_tower";

/* ================= 代码窗口 CRC 尺寸（与烘焙脚本一致） ================= */
#define KKL4_CRC_WINDOW 512

/* 基线常量由 kkl4_baseline.c 独立提供，kkl4.cpp 不包含生成头文件。 */
extern "C" {
extern const uint32_t kKkl4CrcOpen;
extern const uint32_t kKkl4CrcSign;
extern const uint32_t kKkl4CrcCommit;
extern const uint32_t kKkl4CrcCheck;
}

/* ================= SHA-256 / HMAC / hex ================= */
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
#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (RR(x,2)^RR(x,13)^RR(x,22))
#define EP1(x) (RR(x,6)^RR(x,11)^RR(x,25))
#define S0(x) (RR(x,7)^RR(x,18)^((x)>>3))
#define S1(x) (RR(x,17)^RR(x,19)^((x)>>10))

static void sha256(const uint8_t *m, size_t l, uint8_t o[32]) {
    uint32_t h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a;
    uint32_t h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    size_t n = l + 1;
    size_t rem = n % 64;
    size_t pad = rem > 56 ? 120 - rem : 56 - rem;
    n += pad + 8;
    std::vector<uint8_t> buf(n, 0);
    memcpy(buf.data(), m, l);
    buf[l] = 0x80;
    uint64_t bits = (uint64_t)l * 8;
    for (int i = 0; i < 8; i++) buf[n - 1 - i] = (uint8_t)(bits >> (i * 8));
    for (size_t off = 0; off < n; off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)buf[off + i*4] << 24) | ((uint32_t)buf[off + i*4+1] << 16)
                 | ((uint32_t)buf[off + i*4+2] << 8) |  (uint32_t)buf[off + i*4+3];
        }
        for (int i = 16; i < 64; i++) w[i] = S1(w[i-2]) + w[i-7] + S0(w[i-15]) + w[i-16];
        uint32_t a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,hh=h7;
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + EP1(e) + CH(e,f,g) + K256[i] + w[i];
            uint32_t t2 = EP0(a) + MAJ(a,b,c);
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h0+=a; h1+=b; h2+=c; h3+=d; h4+=e; h5+=f; h6+=g; h7+=hh;
    }
    uint32_t hs[8] = {h0,h1,h2,h3,h4,h5,h6,h7};
    for (int i = 0; i < 8; i++) {
        o[i*4]   = (uint8_t)(hs[i] >> 24);
        o[i*4+1] = (uint8_t)(hs[i] >> 16);
        o[i*4+2] = (uint8_t)(hs[i] >> 8);
        o[i*4+3] = (uint8_t)hs[i];
    }
}

static void hmac_sha256(const uint8_t *key, size_t klen,
                        const uint8_t *msg, size_t mlen, uint8_t out[32]) {
    uint8_t k0[64] = {0};
    if (klen > 64) sha256(key, klen, k0); else memcpy(k0, key, klen);
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    std::vector<uint8_t> inner(64 + mlen);
    memcpy(inner.data(), ipad, 64);
    memcpy(inner.data() + 64, msg, mlen);
    uint8_t ih[32];
    sha256(inner.data(), inner.size(), ih);
    std::vector<uint8_t> outer(64 + 32);
    memcpy(outer.data(), opad, 64);
    memcpy(outer.data() + 64, ih, 32);
    sha256(outer.data(), outer.size(), out);
}

static void to_hex(const uint8_t *in, int n, char *out) {
    const char *t = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[i*2] = t[(in[i] >> 4) & 0xF];
        out[i*2+1] = t[in[i] & 0xF];
    }
    out[n*2] = '\0';
}

/* ================= CRC-32（与 zlib 标准一致） ================= */
static uint32_t crc32_bytes(const uint8_t *data, size_t len) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        c ^= data[i];
        for (int j = 0; j < 8; j++) c = (c & 1u) ? ((c >> 1) ^ 0xEDB88320u) : (c >> 1);
    }
    return c ^ 0xFFFFFFFFu;
}

static int maps_holds_code(uintptr_t fn, size_t window) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start = 0, end = 0;
        char perms[8] = {0};
        char path[512] = {0};
        int n = sscanf(line, "%llx-%llx %7s %*s %*s %*s %511[^\n]",
                       &start, &end, perms, path);
        if (n < 3) continue;
        if (perms[0] != 'r' || perms[2] != 'x') continue;
        if (!strstr(path, "libkkl4.so")) continue;
        if ((unsigned long long)fn >= start &&
            (unsigned long long)fn + (unsigned long long)window <= end) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

/* 校验器自身也进入 CRC 窗口：inline hook 校验器会改写它的前几条指令。 */
extern "C" JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Kkl4Native_nativeOpen(JNIEnv *, jclass);
extern "C" JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Kkl4Native_nativeSign(JNIEnv *, jclass, jint, jlong);
extern "C" JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Kkl4Native_nativeCommit(JNIEnv *, jclass, jint, jint);
extern "C" JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Kkl4Native_nativeRollback(JNIEnv *, jclass);

static int crc_window_ok(uintptr_t fn, uint32_t expected) {
    if (fn == 0) return 0;
    if (!maps_holds_code(fn, KKL4_CRC_WINDOW)) return 0;
    return crc32_bytes((const uint8_t *)fn, KKL4_CRC_WINDOW) == expected;
}

extern "C" int kkl4_crc_check(void) {
    int ok = 1;
    ok = ok && crc_window_ok((uintptr_t)&Java_com_fatdog_reverse_Kkl4Native_nativeOpen,
                             kKkl4CrcOpen);
    ok = ok && crc_window_ok((uintptr_t)&Java_com_fatdog_reverse_Kkl4Native_nativeSign,
                             kKkl4CrcSign);
    ok = ok && crc_window_ok((uintptr_t)&Java_com_fatdog_reverse_Kkl4Native_nativeCommit,
                             kKkl4CrcCommit);
    ok = ok && crc_window_ok((uintptr_t)&kkl4_crc_check, kKkl4CrcCheck);
    return ok ? 1 : 0;
}

/* ================= 密钥派生 + 静默投毒 ================= */
static uint8_t g_key[32];
static bool g_ready = false;
static bool g_poisoned = false;

static const uint8_t *real_key() {
    if (!g_ready) {
        std::string tag;
        for (size_t i = 0; i < MARKER_LEN; i++) tag.push_back((char)(MARKER[i] & 0xFF));
        std::string input = tag + SALT;
        sha256((const uint8_t *)input.data(), input.size(), g_key);
        g_ready = true;
    }
    return g_key;
}

static void poison_key() {
    if (!g_poisoned) {
        uint8_t *key = (uint8_t *)real_key();
        key[7] ^= 0x40;
        g_poisoned = true;
    }
}

/* ================= 三点记账状态 ================= */
static volatile uint32_t g_opened = 0;
static volatile uint32_t g_signs = 0;
static volatile uint32_t g_commits = 0;
static volatile int g_last_page = -1;
static volatile uint32_t g_nonce = 0;
static volatile int g_sealed = 0;

static void poison_and_seal() {
    poison_key();
    g_sealed = 1;
}

static int sign_pending() {
    return g_signs == g_commits + 1;
}

static int ledger_ready() {
    if (g_sealed) return 0;
    if (g_opened != 1) return 0;
    if (g_signs != g_commits && !sign_pending()) return 0;
    return 1;
}

static std::string make_status(int crc_ok) {
    char buf[640];
    snprintf(buf, sizeof(buf),
             "锁妖塔守卫自检：\n"
             "  CRC 代码段  : %s\n"
             "  开门记账    : %s\n"
             "  取数记账    : %s\n"
             "  native 回调 : %s\n"
             "  密钥状态    : %s\n"
             "  明文可见    : Fatdog_grim（诱饵）",
             crc_ok ? "通过" : "异常（patch/hook 已改变代码字节）",
             g_opened == 1 ? "已记账" : "未记账",
             g_signs == g_commits ? "无挂账" : (sign_pending() ? "待回调核账" : "异常"),
             sign_pending() ? "待 Java 回调" : (g_commits > 0 ? "已核账" : "未触发"),
             g_poisoned ? "已投毒（服务端将 403）" : "正常");
    return std::string(buf);
}

/* ================= JNI：Kkl4Native ================= */
extern "C" {

JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Kkl4Native_nativeOpen(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    if (g_sealed) return -2;
    if (!kkl4_crc_check()) {
        poison_and_seal();
        return -3;
    }
    uint32_t seed = (uint32_t)time(NULL);
    seed ^= (uint32_t)getpid() * 0x9E3779B9u;
    g_nonce = (seed ^ 0x5A17A11Eu) & 0x7FFFFFFFu;
    g_opened = 1;
    g_signs = 0;
    g_commits = 0;
    g_last_page = -1;
    return 0;
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl4Native_nativeSign(JNIEnv *env, jclass clazz,
                                              jint page, jlong ts) {
    (void)clazz;
    if (!kkl4_crc_check() || !ledger_ready() || g_signs != g_commits) {
        poison_and_seal();
    }
    if (!g_sealed) {
        g_last_page = (int)page;
        g_signs++;
    }
    char msg[96];
    snprintf(msg, sizeof(msg), "page=%d&ts=%lld", (int)page, (long long)ts);
    const uint8_t *key = real_key();
    uint8_t mac[32];
    hmac_sha256(key, 32, (const uint8_t *)msg, strlen(msg), mac);
    char hex[65];
    to_hex(mac, 32, hex);
    return env->NewStringUTF(hex);
}

/* Java 收到第 page 页 count 个数后回调；next sign 前必须把这笔账销掉。 */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Kkl4Native_nativeCommit(JNIEnv *env, jclass clazz,
                                                jint page, jint count) {
    (void)env; (void)clazz;
    if (g_sealed) return -1;
    if (!sign_pending()) return -2;
    if (g_last_page != (int)page) return -3;
    if (count <= 0) return -4;
    g_commits++;
    return 0;
}

JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Kkl4Native_nativeRollback(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    if (g_sealed) return -1;
    if (!sign_pending()) return -2;
    g_signs--;
    return 0;
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl4Native_nativeStatus(JNIEnv *env, jclass clazz) {
    (void)clazz;
    std::string s = make_status(kkl4_crc_check());
    return env->NewStringUTF(s.c_str());
}

} /* extern "C" */
