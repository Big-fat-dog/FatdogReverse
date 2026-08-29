#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <dlfcn.h>
#include <elf.h>

// ============================================================================
// 关卡 33：金刚不坏（native 第三季第 6 关）
//   自完整性校验：加载时对自身可执行段算 CRC32 存基线，每次签名重算比对——
//   任何 inline hook（包括纯观察）都会改字节而被抓；外加记账守卫防整体替换。
//   细节与线索：
//     · 校验器自身区间（K33_ZONE_START ~ K33_ZONE_END）被排除在 CRC 之外——
//       这个"洞"在 IDA 里清晰可见，也正是解法②能安全 hook 校验器的原因；
//     · g_baseline / g_ticks / g_verdict 是普通全局变量——解法③直接内存改写。
//   三条官方解法全开：
//     ① spawn 下 hook JNI_OnLoad 的 onEnter 先装完钩子 → 基线带钩建立永远一致
//     ② 按偏移 hook 校验函数 k33_check（它在排除区间内，改它不动 CRC）
//     ③ Memory 找到 g_baseline 改写成当前实值
//   中招表现同 L32：静默投毒一字节 + assertGuard 报"完整性校验失败"。
// ============================================================================

/* 密钥 "Fatdog_jealous"，UTF-16LE 码元 */
unsigned short KEY33[] = {0x0046,0x0061,0x0074,0x0064,0x006f,0x0067,0x005f,
                          0x006a,0x0065,0x0061,0x006c,0x006f,0x0075,0x0073};
#define KEY33_LEN 14

static volatile int g_poison   = 0;    /* 任一守卫失败即置位 → 签名投毒 */
static volatile int g_running  = 1;
static volatile unsigned int g_baseline = 0;  /* 解法③的目标：基线可写 */
static volatile int g_ticks    = 0;    /* 记账守卫：每次真签名 ++ */
static volatile int g_verdict  = -1;   /* 上一次签名结论：1=干净 0=已污染 */

/* ---------------- 排除区间锚点 ---------------- */

__attribute__((noinline)) void K33_ZONE_START(void) { }
__attribute__((noinline)) void K33_ZONE_END(void)   { }

/* ---------------- CRC32（反射多项式 0xEDB88320） ---------------- */

static unsigned int k33_crc32(const unsigned char *p, size_t n) {
    static unsigned int tab[256];
    static int tab_ready = 0;
    unsigned int crc = 0xFFFFFFFFu;
    size_t i;
    int b;
    if (!tab_ready) {
        for (i = 0; i < 256; i++) {
            unsigned int v = (unsigned int) i;
            int k;
            for (k = 0; k < 8; k++)
                v = (v >> 1) ^ (0xEDB88320u & (0u - (v & 1u)));
            tab[i] = v;
        }
        tab_ready = 1;
    }
    for (i = 0; i < n; i++)
        crc = tab[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

/* ---------------- 可执行段 CRC（挖掉校验器自身的洞） ---------------- */

static unsigned int k33_text_crc(void) {
    Dl_info di;
    const unsigned char *base, *ph, *seg;
    const Elf64_Ehdr *eh;
    const Elf64_Phdr *phd;
    const unsigned char *z0, *z1;
    unsigned int c1, c2;
    size_t len, pre, post;
    int i;

    if (dladdr((void *) &K33_ZONE_START, &di) == 0 || di.dli_fbase == NULL)
        return 0;
    base = (const unsigned char *) di.dli_fbase;
    eh = (const Elf64_Ehdr *) base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return 0;

    z0 = (const unsigned char *) (void *) &K33_ZONE_START;
    z1 = (const unsigned char *) (void *) &K33_ZONE_END;

    ph = base + eh->e_phoff;
    for (i = 0; i < eh->e_phnum; i++) {
        phd = (const Elf64_Phdr *) (ph + (size_t) i * eh->e_phentsize);
        if (phd->p_type != PT_LOAD || !(phd->p_flags & PF_X)) continue;

        seg  = base + phd->p_vaddr;
        len  = (size_t) phd->p_filesz;
        if (z0 < seg) z0 = seg;
        if (z1 > seg + len) z1 = seg + len;
        if (!(z0 >= seg && z1 <= seg + len && z1 > z0))
            return k33_crc32(seg, len);          /* 区间异常就全量算 */

        pre  = (size_t) (z0 - seg);              /* 段首 → 洞前 */
        post = (size_t) ((seg + len) - z1);      /* 洞后 → 段尾 */
        /* 分两段算再合成：等价于对整段挖洞后求 CRC */
        {
            static unsigned int tab[256];
            static int ready = 0;
            unsigned int crc = 0xFFFFFFFFu;
            size_t k;
            int b;
            if (!ready) {
                for (i = 0; i < 256; i++) {
                    unsigned int v = (unsigned int) i;
                    for (b = 0; b < 8; b++)
                        v = (v >> 1) ^ (0xEDB88320u & (0u - (v & 1u)));
                    tab[i] = v;
                }
                ready = 1;
            }
            for (k = 0; k < pre; k++)
                crc = tab[(crc ^ seg[k]) & 0xFF] ^ (crc >> 8);
            for (k = 0; k < post; k++)
                crc = tab[(crc ^ (z1[k])) & 0xFF] ^ (crc >> 8);
            c1 = ~crc;
        }
        (void) c2;
        return c1;
    }
    return 0;
}

/* ---------------- 守卫检查：CRC 一致 + 记账正常 ---------------- */

static int k33_check(void) {
    if (g_baseline == 0) return 0;                       /* 还没建基线 */
    if (k33_text_crc() != g_baseline) return 0;          /* 代码段被动过 */
    if (g_poison) return 0;
    return 1;
}

static void k33_key(char *buf) {
    int i;
    for (i = 0; i < KEY33_LEN; i++) buf[i] = (char) (KEY33[i] & 0xFF);
    buf[KEY33_LEN] = '\0';
    if (g_poison) buf[7] = (char) (buf[7] ^ 0x01);       /* 静默投毒一字节 */
}

static void *k33_guard_thread(void *arg) {
    (void) arg;
    while (g_running) {
        if (!k33_check()) g_poison = 1;
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
Java_com_fatdog_reverse_Fh_nativeSign(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char key[24], msg[64], hex[65];
    unsigned char mac[32];
    static const char hexc[] = "0123456789abcdef";
    int i, mlen;
    (void) clazz;
    g_ticks++;                                   /* 记账：只有真身会走到这里 */
    if (!k33_check()) g_poison = 1;              /* 签名前先体检 */
    g_verdict = g_poison ? 0 : 1;
    k33_key(key);
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

/* 记账守卫：客户端取数前后调用——ticks 原地踏步或结论异常都说明校验链被篡改
 * （整体替换 nativeSign 的打法会跳过记账，在这里现形） */
JNIEXPORT jboolean JNICALL
Java_com_fatdog_reverse_Fh_assertGuard(JNIEnv *env, jclass clazz, jint minTicks) {
    static int last_seen = 0;
    (void) env; (void) clazz;
    if (g_poison) return JNI_FALSE;
    if (g_ticks < minTicks) return JNI_FALSE;
    if (g_ticks == last_seen) return JNI_FALSE;  /* 踏步 = 有人替跑了 */
    last_seen = g_ticks;
    if (g_verdict != 1) return JNI_FALSE;
    return JNI_TRUE;
}

JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Fh_isPoisoned(JNIEnv *env, jclass clazz) {
    (void) env; (void) clazz;
    return g_poison ? 1 : 0;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    pthread_t tid;
    (void) reserved;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    /* 解法①的窗口：hook 本函数 onEnter 时此刻还没建基线，
     * 在这里装完所有钩子，随后基线带着钩子一起建立 → 永远一致 */
    g_baseline = k33_text_crc();
    pthread_create(&tid, NULL, k33_guard_thread, NULL);
    return JNI_VERSION_1_6;
}
