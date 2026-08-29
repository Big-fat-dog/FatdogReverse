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
#include <dlfcn.h>
#include <elf.h>
#include <sys/ptrace.h>

// ============================================================================
// 关卡 34：万法归墟（native 第三季综合卷）
//   动态注册 + 无名 Feistel + 四路反检测 + CRC 自校验 + 记账守卫 + 响应 RC4。
//   请求：POST 表单 page/ts/enc/sign(+dev/ver 噪声)
//     enc  = hex(Feistel8(key, "page=N&ts=T" 零填充))
//     sign = hex(HMAC-SHA256(key, enc))        key = Fatdog_grumpy
//     Feistel8 轮函数 F_i(x)=SHA256(sub_i||x)[:4]，sub_i=SHA256(key||str(i))[:4]
//   响应：{"d": hex(RC4(rsp_key, "page=N|nums=…"))}
//     rsp_key = SHA256("Fatdog_grumpy|rsp")[:16]（密钥派生，教学点）
//   守卫：四路哨兵(maps/端口/线程名/TracerPid) + 可执行段 CRC 基线（挖洞排除
//   校验器）+ assertGuard 记账。任一失守 → 静默投毒一字节 + App 弹一次警告。
//   三条官方路线：纯 Frida（拆守卫→RegisterNatives 抓映射→偏移观察→复刻）/
//   patch so（IDA 废掉 k34_scan 与 CRC）/ unidbg 离线签名机。
// ============================================================================

/* 密钥 "Fatdog_grumpy"，UTF-16LE 码元 */
unsigned short KEY34[] = {0x0046,0x0061,0x0074,0x0064,0x006f,0x0067,0x005f,
                          0x0067,0x0072,0x0075,0x006d,0x0070,0x0079};
#define KEY34_LEN 13

static volatile int g_poison    = 0;
static volatile int g_running   = 1;
static volatile unsigned int g_baseline = 0;
static volatile int g_ticks     = 0;
static volatile int g_verdict   = -1;

static unsigned char k34_subs[8][4];      /* Feistel 子轮密钥 */
static unsigned char k34_rsp[16];         /* 响应 RC4 密钥（派生） */

static int k34_crc_ok(void);              /* 前置声明：守护线程先用后定义 */

/* ---------------- 排除区间锚点（CRC 挖洞线索） ---------------- */

__attribute__((noinline)) void K34_ZONE_START(void) { }
__attribute__((noinline)) void K34_ZONE_END(void)   { }

/* ---------------- CRC32 ---------------- */

static unsigned int k33_crc32_tab[256];
static int k33_tab_ready = 0;

static void k34_crc_init(void) {
    int i, b;
    if (k33_tab_ready) return;
    for (i = 0; i < 256; i++) {
        unsigned int v = (unsigned int) i;
        for (b = 0; b < 8; b++)
            v = (v >> 1) ^ (0xEDB88320u & (0u - (v & 1u)));
        k33_crc32_tab[i] = v;
    }
    k33_tab_ready = 1;
}

static unsigned int k34_crc_span(const unsigned char *p, size_t n) {
    unsigned int crc = 0xFFFFFFFFu;
    size_t i;
    for (i = 0; i < n; i++)
        crc = k33_crc32_tab[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return crc;                              /* 不取反，便于跨段续算 */
}

static unsigned int k34_text_crc(void) {
    Dl_info di;
    const unsigned char *base, *ph, *seg, *z0, *z1;
    const Elf64_Ehdr *eh;
    const Elf64_Phdr *phd;
    unsigned int c = 0xFFFFFFFFu;
    size_t len, pre, post, k;
    int i;

    if (dladdr((void *) &K34_ZONE_START, &di) == 0 || di.dli_fbase == NULL)
        return 0;
    base = (const unsigned char *) di.dli_fbase;
    eh = (const Elf64_Ehdr *) base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return 0;

    z0 = (const unsigned char *) (void *) &K34_ZONE_START;
    z1 = (const unsigned char *) (void *) &K34_ZONE_END;

    ph = base + eh->e_phoff;
    for (i = 0; i < eh->e_phnum; i++) {
        phd = (const Elf64_Phdr *) (ph + (size_t) i * eh->e_phentsize);
        if (phd->p_type != PT_LOAD || !(phd->p_flags & PF_X)) continue;
        seg = base + phd->p_vaddr;
        len = (size_t) phd->p_filesz;
        if (z0 < seg) z0 = seg;
        if (z1 > seg + len) z1 = seg + len;
        if (!(z0 >= seg && z1 <= seg + len && z1 > z0))
            return ~k34_crc_span(seg, len);
        pre  = (size_t) (z0 - seg);
        post = (size_t) ((seg + len) - z1);
        c = k34_crc_span(seg, pre);          /* 洞前 */
        {   /* 续算洞后：crc 从洞前结果继续（未取反状态） */
            for (k = 0; k < post; k++)
                c = k33_crc32_tab[(c ^ z1[k]) & 0xFF] ^ (c >> 8);
            c = ~c;
        }
        return c;
    }
    return 0;
}

/* ---------------- 四路反检测哨兵 ---------------- */

static int k34_detect_maps(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    int hit = 0;
    if (f == NULL) return 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strstr(line, "frida") != NULL || strstr(line, "gadget") != NULL) { hit = 1; break; }
    }
    fclose(f);
    return hit;
}

static int k34_detect_ports(void) {
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
        if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) == 0) { close(s); return 1; }
        close(s);
    }
    return 0;
}

static int k34_detect_threads(void) {
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
            if (strstr(comm, "gum-js-loop") || strstr(comm, "gmain") || strstr(comm, "gdbus"))
                hit = 1;
        }
        fclose(f);
    }
    closedir(d);
    return hit;
}

static int k34_detect_tracer(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    int hit = 0;
    if (f == NULL) return 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            if (atoi(line + 10) != 0) hit = 1;
            break;
        }
    }
    fclose(f);
    return hit;
}

static void k34_scan_once(void) {
    if (k34_detect_maps() | k34_detect_ports()
        | k34_detect_threads() | k34_detect_tracer()) {
        g_poison = 1;
    }
}

static void *k34_guard_thread(void *arg) {
    (void) arg;
    while (g_running) {
        k34_scan_once();
        if (!k34_crc_ok()) g_poison = 1;
        sleep(2);
    }
    return NULL;
}

/* ---------------- SHA-256 / HMAC / RC4 ---------------- */
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

static void k34_rc4(const unsigned char *key, size_t klen,
                    const unsigned char *in, size_t n, unsigned char *out) {
    unsigned char S[256], t;
    int i, j = 0, a = 0, b = 0;
    size_t k;
    for (i = 0; i < 256; i++) S[i] = (unsigned char) i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) & 0xFF;
        t = S[i]; S[i] = S[j]; S[j] = t;
    }
    for (k = 0; k < n; k++) {
        a = (a + 1) & 0xFF;
        b = (b + S[a]) & 0xFF;
        t = S[a]; S[a] = S[b]; S[b] = t;
        out[k] = in[k] ^ S[(S[a] + S[b]) & 0xFF];
    }
}

static void to_hex(const unsigned char *d, int n, char *hex) {
    static const char h[] = "0123456789abcdef";
    int i;
    for (i = 0; i < n; i++) {
        hex[i * 2]     = h[d[i] >> 4];
        hex[i * 2 + 1] = h[d[i] & 0x0f];
    }
    hex[n * 2] = '\0';
}

/* ---------------- Feistel-8 ---------------- */

static void k34_feist_init(void) {
    sha256_ctx c;
    unsigned char seed[16], digest[32];
    int i;
    /* sub_i = SHA256(KEY34 || str(i))[:4] */
    memcpy(seed, KEY34, KEY34_LEN);
    for (i = 0; i < 8; i++) {
        seed[KEY34_LEN]     = (unsigned char) ('0' + i);
        seed[KEY34_LEN + 1] = 0;
        sha256_init(&c); sha256_update(&c, seed, (size_t)(KEY34_LEN + 1));
        sha256_final(&c, digest);
        memcpy(k34_subs[i], digest, 4);
    }
    /* rsp_key = SHA256("Fatdog_grumpy|rsp")[:16]
     * 种子在运行时拼装（UTF-16 低位字节即 ASCII），避免明文进 .rodata */
    {
        unsigned char rs[24];
        static const char tail[] = {'|', 'r', 's', 'p'};
        memcpy(rs, KEY34, KEY34_LEN);
        memcpy(rs + KEY34_LEN, tail, 4);
        sha256_init(&c);
        sha256_update(&c, rs, (size_t)(KEY34_LEN + 4));
        sha256_final(&c, digest);
        memcpy(k34_rsp, digest, 16);
    }
}

/* F_i(x)：SHA256(sub_i || x)[:4] */
static void k34_F(int i, const unsigned char *x, unsigned char *out4) {
    sha256_ctx c;
    unsigned char dg[32];
    sha256_init(&c);
    sha256_update(&c, k34_subs[i], 4);
    sha256_update(&c, x, 4);
    sha256_final(&c, dg);
    memcpy(out4, dg, 4);
}

/* 加密一步 E_i(L,R)=(R, L^F_i(L))；整块按大端四字节处理 */
static void k34_feist_enc(unsigned char *blk) {
    unsigned char L[4], R[4], t[4];
    int i, j;
    memcpy(L, blk, 4);
    memcpy(R, blk + 4, 4);
    for (i = 0; i < 8; i++) {
        k34_F(i, L, t);
        for (j = 0; j < 4; j++) t[j] = (unsigned char) (L[j] ^ t[j]);
        memcpy(L, R, 4);
        memcpy(R, t, 4);
    }
    memcpy(blk, L, 4);
    memcpy(blk + 4, R, 4);
}

/* ---------------- 守卫与密钥 ---------------- */

static int k34_crc_ok(void) {
    if (g_baseline == 0) return 0;
    return k34_text_crc() == g_baseline;
}

static int k34_check(void) {
    if (g_poison) return 0;
    if (!k34_crc_ok()) return 0;
    return 1;
}

static void k34_key(char *buf) {
    int i;
    for (i = 0; i < KEY34_LEN; i++) buf[i] = (char) (KEY34[i] & 0xFF);
    buf[KEY34_LEN] = '\0';
    if (g_poison) buf[8] = (char) (buf[8] ^ 0x01);       /* g → f 一字之差 */
}

/* ---------------- 真身实现（static，动态注册绑定，导出表无名） ---------------- */

static jstring k34_pack(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char key[24], msg[80], hex[161];
    unsigned char buf[80];
    int klen, mlen, padded, i;
    (void) clazz;
    g_ticks++;
    if (!k34_check()) g_poison = 1;
    g_verdict = g_poison ? 0 : 1;
    k34_key(key);
    mlen = snprintf(msg, sizeof(msg), "page=%d&ts=%lld", (int) page, (long long) ts);
    padded = (mlen + 7) / 8 * 8;                         /* 零填充到 8 的倍数 */
    memset(buf, 0, (size_t) padded);
    memcpy(buf, msg, (size_t) mlen);
    for (i = 0; i < padded; i += 8) {
        k34_feist_enc(buf + i);
    }
    to_hex(buf, padded, hex);
    return (*env)->NewStringUTF(env, hex);
}

static jstring k34_sign(JNIEnv *env, jclass clazz, jstring encHex) {
    char key[24];
    const char *enc;
    unsigned char mac[32];
    char hex[65];
    int klen;
    size_t elen;
    (void) clazz;
    k34_key(key);
    enc = (*env)->GetStringUTFChars(env, encHex, NULL);
    if (enc == NULL) return (*env)->NewStringUTF(env, "");
    elen = strlen(enc);
    hmac_sha256((const unsigned char *) key, strlen(key),
                (const unsigned char *) enc, elen, mac);
    (*env)->ReleaseStringUTFChars(env, encHex, enc);
    to_hex(mac, 32, hex);
    return (*env)->NewStringUTF(env, hex);
}

static jstring k34_unwrap(JNIEnv *env, jclass clazz, jstring dHex) {
    const char *d;
    size_t n, dn;
    unsigned char *raw, *plain;
    char *out;
    jstring ret;
    (void) clazz;
    d = (*env)->GetStringUTFChars(env, dHex, NULL);
    if (d == NULL) return (*env)->NewStringUTF(env, "");
    n = strlen(d);
    dn = n / 2;
    raw   = (unsigned char *) malloc(dn + 1);
    plain = (unsigned char *) malloc(dn + 1);
    out   = (char *) malloc(dn + 1);
    if (raw && plain && out) {
        size_t i;
        int v;
        for (i = 0; i < dn; i++) {
            v = 0;
            sscanf(d + i * 2, "%2x", &v);
            raw[i] = (unsigned char) v;
        }
        k34_rc4(k34_rsp, 16, raw, dn, plain);
        plain[dn] = 0;
        memcpy(out, plain, dn + 1);
        ret = (*env)->NewStringUTF(env, out);
    } else {
        ret = (*env)->NewStringUTF(env, "");
    }
    free(raw); free(plain); free(out);
    (*env)->ReleaseStringUTFChars(env, dHex, d);
    return ret;
}

static jboolean k34_assert(JNIEnv *env, jclass clazz, jint minTicks) {
    static int last_seen = 0;
    (void) env; (void) clazz;
    if (g_poison) return JNI_FALSE;
    if (!k34_crc_ok()) return JNI_FALSE;
    if (g_ticks < minTicks) return JNI_FALSE;
    if (g_ticks == last_seen) return JNI_FALSE;
    last_seen = g_ticks;
    if (g_verdict != 1) return JNI_FALSE;
    return JNI_TRUE;
}

static jint k34_poisoned(JNIEnv *env, jclass clazz) {
    (void) env; (void) clazz;
    return g_poison ? 1 : 0;
}

/* ---------------- 诱饵导出（静态注册同名/近名，全被动态覆盖） ---------------- */

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Yh_nativePack(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char hex[65];
    static const char hexc[] = "0123456789abcdef";
    int i;
    (void) clazz; (void) page; (void) ts;
    for (i = 0; i < 64; i++) hex[i] = hexc[(i * 7 + 3) & 0xF];
    hex[64] = '\0';
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Yh_sign(JNIEnv *env, jclass clazz, jstring encHex) {
    (void) clazz; (void) encHex;
    return (*env)->NewStringUTF(env,
        "0f1e2d3c5b6a7988" "0f1e2d3c5b6a7988" "0f1e2d3c5b6a7988" "0f1e2d3c5b6a7988");
}

/* ---------------- JNI_OnLoad：注册真身 + 建基线 + 起哨兵 ---------------- */

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    jclass cls;
    pthread_t tid;
    JNINativeMethod ms[5];
    (void) reserved;

    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;

    ptrace(PTRACE_TRACEME, 0, 0, 0);         /* 占坑：挡 gdb/IDA attach */
    k34_crc_init();
    k34_feist_init();

    cls = (*env)->FindClass(env, "com/fatdog/reverse/Yh");   /* 根包类，R8 不改名 */
    if (cls == NULL) return JNI_ERR;

    ms[0].name = "nativePack";  ms[0].signature = "(IJ)Ljava/lang/String;";
    ms[0].fnPtr = (void *) k34_pack;
    ms[1].name = "nativeSign";  ms[1].signature = "(Ljava/lang/String;)Ljava/lang/String;";
    ms[1].fnPtr = (void *) k34_sign;
    ms[2].name = "nativeUnwrap";ms[2].signature = "(Ljava/lang/String;)Ljava/lang/String;";
    ms[2].fnPtr = (void *) k34_unwrap;
    ms[3].name = "assertGuard"; ms[3].signature = "(I)Z";
    ms[3].fnPtr = (void *) k34_assert;
    ms[4].name = "isPoisoned";  ms[4].signature = "()I";
    ms[4].fnPtr = (void *) k34_poisoned;
    if ((*env)->RegisterNatives(env, cls, ms, 5) != JNI_OK) return JNI_ERR;

    g_baseline = k34_text_crc();             /* 解法①窗口：onEnter 抢跑时装钩子 */
    k34_scan_once();
    pthread_create(&tid, NULL, k34_guard_thread, NULL);
    return JNI_VERSION_1_6;
}
