#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ptrace.h>

// ============================================================================
// 关卡 32：心魔哨兵（native 第三季第 5 关）
//   四路反检测哨兵在后台线程轮询：
//     ① /proc/self/maps 里搜 frida / gadget 特征
//     ② 试探本机 frida 默认端口 27042 / 27043
//     ③ 枚举 /proc/self/task/*/comm 找 gum-js-loop / gmain / gdbus 特征线程
//     ④ /proc/self/status 的 TracerPid 非 0（防 gdb/IDA 调试器；Frida 不走 ptrace）
//   另加 ptrace(PTRACE_TRACEME) 自占调试位——挡的是后来的 gdb，不是 Frida。
//   中招不闪退：g_poison 静默置位，签名密钥被动一个字节 → 全部错签；
//   App 侧查询 isPoisoned 后弹一次警告窗（教育向：只警告，不拉黑不封号）。
// ============================================================================

/* 密钥 "Fatdog_anxious"，UTF-16LE 码元（非 const 全局防折叠） */
unsigned short KEY32[] = {0x0046,0x0061,0x0074,0x0064,0x006f,0x0067,0x005f,
                          0x0061,0x006e,0x0078,0x0069,0x006f,0x0075,0x0073};
#define KEY32_LEN 14

static volatile int g_poison = 0;
static volatile int g_running = 1;

static void k32_key(char *buf) {
    int i;
    for (i = 0; i < KEY32_LEN; i++) buf[i] = (char) (KEY32[i] & 0xFF);
    buf[KEY32_LEN] = '\0';
    if (g_poison) buf[4] = (char) (buf[4] ^ 0x01);   /* 静默投毒：o → n 一字之差 */
}

/* ---------------- 四路哨兵 ---------------- */

static int k32_detect_maps(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    int hit = 0;
    if (f == NULL) return 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strstr(line, "frida") != NULL || strstr(line, "gadget") != NULL) {
            hit = 1;
            break;
        }
    }
    fclose(f);
    return hit;
}

static int k32_detect_ports(void) {
    static const int ports[2] = {27042, 27043};
    int i;
    for (i = 0; i < 2; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;
        if (s < 0) return 0;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((unsigned short) ports[i]);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) == 0) {
            close(s);
            return 1;                       /* 端口有人监听 */
        }
        close(s);
    }
    return 0;
}

static int k32_detect_threads(void) {
    DIR *d = opendir("/proc/self/task");
    struct dirent *de;
    int hit = 0;
    if (d == NULL) return 0;
    while ((de = readdir(d)) != NULL && !hit) {
        char path[128], comm[64];
        FILE *f;
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", de->d_name);
        f = fopen(path, "r");
        if (f == NULL) continue;
        if (fgets(comm, sizeof(comm), f) != NULL) {
            if (strstr(comm, "gum-js-loop") || strstr(comm, "gmain")
                || strstr(comm, "gdbus")) {
                hit = 1;
            }
        }
        fclose(f);
    }
    closedir(d);
    return hit;
}

static int k32_detect_tracer(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    int hit = 0;
    if (f == NULL) return 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            if (pid != 0) hit = 1;
            break;
        }
    }
    fclose(f);
    return hit;
}

static void k32_scan_once(void) {
    if (k32_detect_maps() | k32_detect_ports()
        | k32_detect_threads() | k32_detect_tracer()) {
        g_poison = 1;                        /* 静默置位，不打扰前台 */
    }
}

static void *k32_guard_thread(void *arg) {
    (void) arg;
    while (g_running) {
        k32_scan_once();
        sleep(2);
    }
    return NULL;
}

/* ---------------- SHA-256 / HMAC-SHA256（紧凑实现） ---------------- */
typedef struct {
    unsigned int h[8];
    unsigned char buf[64];
    unsigned long long total;
} sha256_ctx;

static const unsigned int K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static unsigned int rotr(unsigned int x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256_block(sha256_ctx *c, const unsigned char *p) {
    unsigned int w[64];
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = ((unsigned int) p[i * 4] << 24) | ((unsigned int) p[i * 4 + 1] << 16)
             | ((unsigned int) p[i * 4 + 2] << 8) | (unsigned int) p[i * 4 + 3];
    }
    for (i = 16; i < 64; i++) {
        unsigned int s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        unsigned int s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    {
        unsigned int a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
        unsigned int e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
        for (i = 0; i < 64; i++) {
            unsigned int S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            unsigned int ch = (e & f) ^ ((~e) & g);
            unsigned int t1 = h + S1 + ch + K256[i] + w[i];
            unsigned int S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            unsigned int maj = (a & b) ^ (a & cc) ^ (b & cc);
            unsigned int t2 = S0 + maj;
            h = g; g = f; f = e; e = d + t1;
            d = cc; cc = b; b = a; a = t1 + t2;
        }
        c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
        c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
    }
}

static void sha256_init(sha256_ctx *c) {
    c->h[0] = 0x6a09e667u; c->h[1] = 0xbb67ae85u;
    c->h[2] = 0x3c6ef372u; c->h[3] = 0xa54ff53au;
    c->h[4] = 0x510e527fu; c->h[5] = 0x9b05688cu;
    c->h[6] = 0x1f83d9abu; c->h[7] = 0x5be0cd19u;
    c->total = 0;
}

static void sha256_update(sha256_ctx *c, const unsigned char *data, size_t len) {
    size_t used, rem, i;
    c->total += len;
    used = (size_t) ((c->total - len) & 63);
    rem = 64 - used;
    if (len >= rem) {
        memcpy(c->buf + used, data, rem);
        sha256_block(c, c->buf);
        for (i = rem; i + 64 <= len; i += 64) {
            sha256_block(c, data + i);
        }
        data += i;
        len -= i;
        used = 0;
    }
    memcpy(c->buf + used, data, len);
}

static void sha256_final(sha256_ctx *c, unsigned char out[32]) {
    unsigned long long bits = c->total * 8;
    unsigned char pad[128];
    size_t used = (size_t) (c->total & 63);
    size_t padlen = (used < 56) ? (56 - used) : (120 - used);
    int i;
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    for (i = 0; i < 8; i++) {
        pad[padlen + i] = (unsigned char) (bits >> (56 - 8 * i));
    }
    sha256_update(c, pad, padlen + 8);
    for (i = 0; i < 8; i++) {
        out[i * 4]     = (unsigned char) (c->h[i] >> 24);
        out[i * 4 + 1] = (unsigned char) (c->h[i] >> 16);
        out[i * 4 + 2] = (unsigned char) (c->h[i] >> 8);
        out[i * 4 + 3] = (unsigned char) (c->h[i]);
    }
}

static void hmac_sha256(const unsigned char *key, size_t klen,
                        const unsigned char *msg, size_t mlen,
                        unsigned char out[32]) {
    unsigned char k[64];
    unsigned char ipad[64], opad[64], inner[32];
    sha256_ctx c;
    int i;
    memset(k, 0, sizeof(k));
    if (klen > 64) {
        sha256_init(&c); sha256_update(&c, key, klen); sha256_final(&c, k);
    } else {
        memcpy(k, key, klen);
    }
    for (i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    sha256_init(&c); sha256_update(&c, ipad, 64);
    sha256_update(&c, msg, mlen); sha256_final(&c, inner);
    sha256_init(&c); sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32); sha256_final(&c, out);
}

/* ---------------- JNI 入口 ---------------- */

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bt_nativeSign(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char key[24], msg[64], hex[65];
    unsigned char mac[32];
    static const char hexc[] = "0123456789abcdef";
    int i, mlen;
    (void) clazz;
    k32_key(key);                            /* 可能已被投毒的一字之差 */
    mlen = snprintf(msg, sizeof(msg), "page=%d&ts=%lld", (int) page, (long long) ts);
    hmac_sha256((const unsigned char *) key, strlen(key),
                (const unsigned char *) msg, (size_t) mlen, mac);
    for (i = 0; i < 32; i++) {
        hex[i * 2]     = hexc[mac[i] >> 4];
        hex[i * 2 + 1] = hexc[mac[i] & 0x0f];
    }
    hex[64] = '\0';
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Bt_isPoisoned(JNIEnv *env, jclass clazz) {
    (void) env; (void) clazz;
    return g_poison ? 1 : 0;                 /* App 侧据此弹一次警告窗 */
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    pthread_t tid;
    (void) reserved;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    /* 占坑：挡住后来的 gdb/IDA attach（Frida 不走 ptrace，此招对它无效——教学点） */
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    /* 加载瞬间先扫一遍；再起守护线程每 2 秒轮询 */
    k32_scan_once();
    pthread_create(&tid, NULL, k32_guard_thread, NULL);
    return JNI_VERSION_1_6;
}
