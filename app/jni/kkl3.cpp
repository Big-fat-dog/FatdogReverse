/*
 * 太玄之初 KKL3：断魂谷——四路反调试/反 Frida 哨兵 + 静默投毒（教学版）。
 *
 * libkkl3.so 不直接判胜：玩家每次翻页取数都由 nativeSign() 先跑哨兵。
 * 任一哨兵命中就把 HMAC 密钥的固定位翻掉并永久投毒，之后签出的请求
 * 全部 403。数据只在本地服务端 /api/kkl3，所以"绕过检测"和"拿到数据"
 * 是两件事；检测按钮本身永远不会通关。
 *
 * 四路哨兵：
 *   ① ptrace/TracerPid：/proc/self/status 被附加痕迹
 *   ② maps：frida / gadget / librun / gum-js 等加载特征
 *   ③ 端口：connect 127.0.0.1 27042-27044（frida-server 默认监听）
 *   ④ 线程：遍历 /proc/self/task 各线程 comm 文件，查 gum-js-loop / gmain / gdbus 等
 *
 * 标记（真）：Fatdog_quell — UTF-16 码元藏 .data。
 * 诱饵（假）：Fatdog_quiet — 一字之差。
 */
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ================= 标记：真 UTF-16 / 诱饵明文 ================= */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F, 0x0071, 0x0075, 0x0065, 0x006C, 0x006C
};
#define MARKER_LEN (sizeof(MARKER) / sizeof(jchar))

static const char DECOY[] = "Fatdog_quiet";

/* ================= 服务端同款派生盐 ================= */
static const char SALT[] = "|kkl3_valley";

/* ================= SHA-256 ================= */
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

/* ================= 真密钥派生 ================= */
static uint8_t g_key[32];
static bool g_ready = false;
static volatile bool g_poisoned = false;
static volatile int g_bits = 0;

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

/* ================= 四路哨兵 ================= */
static int detect_tracer(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    int tid = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tid = atoi(line + 10);
            break;
        }
    }
    fclose(f);
    return tid != 0 ? 1 : 0;
}

static int detect_maps(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), f) && !found) {
        if (strstr(line, "frida") || strstr(line, "gadget") ||
            strstr(line, "librun") || strstr(line, "gum-js") ||
            strstr(line, "linjector")) {
            found = 1;
        }
    }
    fclose(f);
    return found;
}

static int detect_port(void) {
    static const int PORTS[] = {27042, 27043, 27044};
    for (int i = 0; i < 3; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)PORTS[i]);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        struct timeval tv = {0, 300000};
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        int r = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        close(fd);
        if (r == 0) return 1;
    }
    return 0;
}

static int detect_threads(void) {
    DIR *d = opendir("/proc/self/task");
    if (!d) return 0;
    struct dirent *de;
    int found = 0;
    while ((de = readdir(d)) != NULL && !found) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        char path[80];
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", de->d_name);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        char name[96];
        int n = (int)read(fd, name, sizeof(name) - 1);
        close(fd);
        if (n <= 0) continue;
        name[n] = '\0';
        while (n > 0 && (name[n-1] == '\n' || name[n-1] == '\r')) name[--n] = '\0';
        if (strstr(name, "gum-js-loop") || strstr(name, "gmain") ||
            strstr(name, "gdbus") || strstr(name, "pool-frida") ||
            strstr(name, "frida")) {
            found = 1;
        }
    }
    closedir(d);
    return found;
}

/* ================= 综合扫描：返回 bitmask，命中即投毒 ================= */
static int run_sentinels(bool poison) {
    int tracer = detect_tracer();
    int maps = detect_maps();
    int port = detect_port();
    int thr = detect_threads();
    int bits = (tracer ? 1 : 0) | (maps ? 2 : 0) | (port ? 4 : 0) | (thr ? 8 : 0);
    g_bits = bits;
    if (poison && bits != 0 && !g_poisoned) {
        /* 固定翻第 8 个密钥字节的第 7 位：服务端验签必然失败 */
        uint8_t *key = (uint8_t *)real_key();
        key[7] ^= 0x40;
        g_poisoned = true;
    }
    return bits;
}

static std::string make_status(int bits) {
   char buf[512];
   snprintf(buf, sizeof(buf),
            "哨兵自检：\n"
            "  ptrace/TracerPid : %s\n"
            "  maps 加载特征    : %s\n"
            "  27042 端口       : %s\n"
            "  frida 线程名     : %s\n"
            "  密钥状态         : %s\n"
            "  明文可见         : Fatdog_quiet（诱饵）",
            (bits & 1) ? "命中" : "安全",
            (bits & 2) ? "命中" : "安全",
            (bits & 4) ? "命中" : "安全",
            (bits & 8) ? "命中" : "安全",
            g_poisoned ? "已投毒（服务端将 403）" : "正常");
   return std::string(buf);
}

/* ================= JNI：Kkl3Native ================= */
extern "C" {

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl3Native_nativeStatus(JNIEnv *env, jclass clazz) {
    (void)clazz;
    int bits = run_sentinels(false);
    std::string s = make_status(bits);
    return env->NewStringUTF(s.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl3Native_nativeSign(JNIEnv *env, jclass clazz,
                                              jint page, jlong ts) {
    (void)clazz;
    run_sentinels(true);
    char msg[80];
    snprintf(msg, sizeof(msg), "page=%d&ts=%lld", (int)page, (long long)ts);
    const uint8_t *key = real_key();
    uint8_t mac[32];
    hmac_sha256(key, 32, (const uint8_t *)msg, strlen(msg), mac);
    char hex[65];
    to_hex(mac, 32, hex);
    return env->NewStringUTF(hex);
}

JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Kkl3Native_nativePoisoned(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return g_poisoned ? 1 : 0;
}

} /* extern "C" */
