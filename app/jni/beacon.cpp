/* 自动生成：python gen_kkl3.py —— 请勿手改。 */
/* 太玄之初 KKL3 断魂谷 · 四 so 编队（门面/国密/摘要/守卫）。 */

/*
 * beacon —— 太玄之初 KKL3 断魂谷的 JNI 门面。
 *
 * 本 so 是全关**唯一**导出 Java_ 符号的库；它自身不含任何算法，
 * 全部内核靠 dlsym(RTLD_DEFAULT) 从其它三个 so 取：
 *     bs_seal/bs_hex（basalt）国密 SM4-ECB 与十六进制
 *     ig_tally    （ingot）    MD5 摘要
 *     hb_scan     （harbor）   完整性守卫
 * 主钥由 Java 业务片派生后作为参数传入（本关 VM 已下沉，见 gen 文档）。
 * 缺任一内核 → 自检报"内核缺失"，签名返回空串。
 */
#include <jni.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

typedef int  (*fn_seal)(const uint8_t *, const uint8_t *, size_t, uint8_t *);
typedef int  (*fn_unseal)(const uint8_t *, const uint8_t *, size_t, uint8_t *);
typedef void (*fn_hex)(const uint8_t *, size_t, char *);
typedef void (*fn_tally)(const uint8_t *, size_t, uint8_t *);
typedef void (*fn_ihex)(const uint8_t *, int, char *);
typedef int  (*fn_scan)(int *);

static fn_seal    g_seal = NULL;
static fn_unseal  g_unseal = NULL;
static fn_hex     g_hex = NULL;
static fn_tally   g_tally = NULL;
static fn_ihex    g_ihex = NULL;
static fn_scan    g_scan = NULL;

static volatile int g_poisoned = 0;
static volatile int g_last_bits = 0;

static void bind_kernels(void) {
    if (g_seal) return;
    g_seal   = (fn_seal)   dlsym(RTLD_DEFAULT, "bs_seal");
    g_unseal = (fn_unseal) dlsym(RTLD_DEFAULT, "bs_unseal");
    g_hex    = (fn_hex)    dlsym(RTLD_DEFAULT, "bs_hex");
    g_tally  = (fn_tally)  dlsym(RTLD_DEFAULT, "ig_tally");
    g_ihex   = (fn_ihex)   dlsym(RTLD_DEFAULT, "ig_hex");
    g_scan   = (fn_scan)   dlsym(RTLD_DEFAULT, "hb_scan");
}

static int kernel_missing(void) {
    return !(g_seal && g_hex && g_tally && g_ihex && g_scan);
}

/* 翻位投毒：让本地派生出的主钥与服务端不再一致（服务端恒 403）。 */
static void poison(uint8_t *seed) {
    if (g_poisoned) return;
    seed[7] ^= 0x40;
    g_poisoned = 1;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl3Native_nativeStatus(JNIEnv *env, jclass) {
    bind_kernels();
    char buf[512];
    if (kernel_missing()) {
        snprintf(buf, sizeof(buf),
                 "内核编队不完整：国密 %s / 摘要 %s / 守卫 %s\n"
                 "lib/ 下四个 so 缺一不可。",
                 g_seal ? "在位" : "缺失",
                 g_tally ? "在位" : "缺失", g_scan ? "在位" : "缺失");
        return env->NewStringUTF(buf);
    }
    int bits = 0;
    g_scan(&bits);
    g_last_bits = bits;
    int hit = ((bits & 1) ? 1 : 0) + ((bits & 2) ? 1 : 0) + ((bits & 4) ? 1 : 0) + ((bits & 8) ? 1 : 0);
    snprintf(buf, sizeof(buf),
             "完整性自检（命中 %d 项，>=2 触发投毒）：\n"
             "  调试器痕迹 : %s\n"
             "  可写可执行段 : %s\n"
             "  断点痕迹   : %s\n"
             "  模拟器环境 : %s\n"
             "  主钥状态   : %s",
             hit,
             (bits & 1) ? "命中" : "安全", (bits & 2) ? "命中" : "安全",
             (bits & 4) ? "命中" : "安全", (bits & 8) ? "命中" : "安全",
             g_poisoned ? "已污染（服务端将拒绝）" : "正常");
    return env->NewStringUTF(buf);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl3Native_nativeSign(JNIEnv *env, jclass, jbyteArray seedArr, jint page, jlong ts) {
    bind_kernels();
    if (kernel_missing()) return env->NewStringUTF("");
    int bits = 0;
    g_scan(&bits);
    g_last_bits = bits;
    int hit = ((bits & 1) ? 1 : 0) + ((bits & 2) ? 1 : 0) + ((bits & 4) ? 1 : 0) + ((bits & 8) ? 1 : 0);

    uint8_t seed[16];
    if (seedArr == NULL || env->GetArrayLength(seedArr) != 16) {
        g_poisoned = 1;
        return env->NewStringUTF("");
    }
    env->GetByteArrayRegion(seedArr, 0, 16, (jbyte *)seed);
    if (hit >= 2) poison(seed);

    char payload[64];
    int pl = snprintf(payload, sizeof(payload), "page=%d&ts=%lld", (int)page, (long long)ts);

    uint8_t ct[128];
    int cl = g_seal(seed, (const uint8_t *)payload, (size_t)pl, ct);
    if (cl <= 0) { g_poisoned = 1; return env->NewStringUTF(""); }
    char enc[300];
    g_hex(ct, (size_t)cl, enc);

    char kh[40];
    g_ihex(seed, 16, kh);
    char msg[400];
    snprintf(msg, sizeof(msg), "%s%s", kh, enc);
    uint8_t mac[16];
    g_tally((const uint8_t *)msg, strlen(msg), mac);
    char sign[40];
    g_ihex(mac, 16, sign);

    char out[400];
    snprintf(out, sizeof(out), "%s|%s", enc, sign);
    return env->NewStringUTF(out);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Kkl3Native_nativePoisoned(JNIEnv *env, jclass) {
    (void)env;
    return g_poisoned ? 1 : 0;
}

/* ============ 多 DEX 装载辅助（§4.4 方法体抽取 + 链式加载） ============ */

/* 片 key = MD5(真标记 + 片 key 盐)；key 盐按片号选（edge/guard/grip/blade/hilt）。 */
static const char *K_SALT[5] = {
    "|kkl3_edge_vein", "|kkl3_guard_vein", "|kkl3_grip_vein",
    "|kkl3_blade_vein", "|kkl3_hilt_vein"
};

static void shard_key(int shard, uint8_t out[16]) {
    /* MD5("Fatdog_quell" + K_SALT[shard]) */
    std::string s = std::string("Fatdog_quell") + K_SALT[shard];
    g_tally((const uint8_t *)s.data(), s.size(), out);
}

/* 解密一片桩化 dex：SM4-ECB 解 + 去 PKCS7。 */
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_fatdog_reverse_Kkl3Native_nativeFold(JNIEnv *env, jclass, jbyteArray enc, jint shard) {
    bind_kernels();
    if (kernel_missing() || shard < 0 || shard >= 5) return NULL;
    jsize n = env->GetArrayLength(enc);
    if (n <= 0 || (n % 16) != 0) return NULL;
    std::vector<uint8_t> raw((size_t)n);
    env->GetByteArrayRegion(enc, 0, n, (jbyte *)raw.data());
    uint8_t key[16];
    shard_key((int)shard, key);
    std::vector<uint8_t> out((size_t)n);
    int m = g_unseal(key, raw.data(), (size_t)n, out.data());
    if (m <= 0) return NULL;
    jbyteArray r = env->NewByteArray(m);
    if (r) env->SetByteArrayRegion(r, 0, m, (const jbyte *)out.data());
    return r;
}

/* 回填方法体：把抽取 bin 里的真实 code_item 覆盖回桩化 dex 的原位置。 */
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_fatdog_reverse_Kkl3Native_nativeRebind(JNIEnv *env, jclass,
                                                jbyteArray stubDex, jbyteArray extractBin) {
    if (stubDex == NULL || extractBin == NULL) return NULL;
    jsize dn = env->GetArrayLength(stubDex);
    jsize bn = env->GetArrayLength(extractBin);
    if (dn <= 0 || bn < 5) return NULL;
    std::vector<uint8_t> dex((size_t)dn);
    std::vector<uint8_t> bin((size_t)bn);
    env->GetByteArrayRegion(stubDex, 0, dn, (jbyte *)dex.data());
    env->GetByteArrayRegion(extractBin, 0, bn, (jbyte *)bin.data());
    if (bin[0] != 'k' || bin[1] != 'k' || bin[2] != 'l' || bin[3] != '3' || bin[4] != 'x') {
        return NULL;
    }
    uint32_t count = 0;
    memcpy(&count, bin.data() + 5, 4);
    size_t off = 9;
    for (uint32_t k = 0; k < count; k++) {
        if (off + 12 > bin.size()) return NULL;
        uint32_t method_idx, code_off, code_len;
        memcpy(&method_idx, bin.data() + off, 4); off += 4;
        memcpy(&code_off, bin.data() + off, 4);   off += 4;
        memcpy(&code_len, bin.data() + off, 4);   off += 4;
        if (off + code_len > bin.size()) return NULL;
        if (code_off + code_len > dex.size()) return NULL;
        memcpy(dex.data() + code_off, bin.data() + off, code_len);
        off += code_len;
    }
    jbyteArray r = env->NewByteArray((jsize)dn);
    if (r) env->SetByteArrayRegion(r, 0, (jsize)dn, (const jbyte *)dex.data());
    return r;
}
