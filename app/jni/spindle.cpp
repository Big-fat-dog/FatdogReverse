/* 自动生成：python gen_kkl5.py —— 请勿手改。 */
/* 太玄之初 KKL5 诛仙台 · 五 so 编队（门面/虚拟机/复合分组/摘要/守卫）。 */

/*
 * spindle —— 太玄之初 KKL5 诛仙台的 JNI 门面。
 *
 * 本 so 是全关**唯一**导出 Java_ 符号的库；它自身不含任何算法，
 * 全部内核靠 dlsym(RTLD_DEFAULT) 从其它四个 so 取：
 *     vl_derive      （vellum）内存机虚拟机派生主钥（32B）
 *     nm_seal/nm_unseal/nm_hex（nimbus）SM4-CBC+AES-CTR 复合与十六进制
 *     tl_tally/tl_hex（tallow）MD5 摘要
 *     wr_scan        （wraith）完整性守卫
 * 缺任一内核 → 自检报"内核缺失"，签名返回空串。
 *
 * 真标记以 UTF-16 码元藏在本文件的 .data（MK5[]），运行时逐字降 ASCII 后
 * 与 salt 拼成输入缓冲喂给虚拟机——标记**不进入字节码**，字节码里只有取数下标。
 */
#include <jni.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kkl5_vm_program.h"

typedef bool (*fn_derive)(const uint8_t *, size_t, const uint8_t *, size_t,
                          const uint8_t *, size_t, const uint8_t *, size_t,
                          uint8_t *, int);
typedef int  (*fn_seal)(const uint8_t *, const uint8_t *, const uint8_t *,
                        const uint8_t *, size_t, uint8_t *);
typedef int  (*fn_unseal)(const uint8_t *, const uint8_t *, const uint8_t *, size_t, uint8_t *);
typedef void (*fn_hex)(const uint8_t *, size_t, char *);
typedef void (*fn_tally)(const uint8_t *, size_t, uint8_t *);
typedef void (*fn_ihex)(const uint8_t *, int, char *);
typedef int  (*fn_scan)(int *);

static fn_derive g_derive = NULL;
static fn_seal   g_seal = NULL;
static fn_unseal g_unseal = NULL;
static fn_hex    g_hex = NULL;
static fn_tally  g_tally = NULL;
static fn_ihex   g_ihex = NULL;
static fn_scan   g_scan = NULL;

static volatile int g_poisoned = 0;

/* ================= 真标记：UTF-16 藏匿（const volatile 保证不被折叠成立即数） ================= */
static const volatile jchar MK5[] = { 0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067, 0x005F, 0x0061, 0x0073, 0x0063, 0x0065, 0x006E, 0x0064 };
#define MK5_LEN ((int)(sizeof(MK5) / sizeof(jchar)))

/* 明文诱饵：与真标记仅末位一字之差（d/t），由 kd_seal_tag() 引用，保证进 .rodata */
static const char DECOY[] = "Fatdog_ascent";
static const char SALT[]  = "|kkl5_altar";

static void bind_kernels(void) {
    if (g_derive) return;
    g_derive = (fn_derive)dlsym(RTLD_DEFAULT, "vl_derive");
    g_seal   = (fn_seal)  dlsym(RTLD_DEFAULT, "nm_seal");
    g_unseal = (fn_unseal)dlsym(RTLD_DEFAULT, "nm_unseal");
    g_hex    = (fn_hex)   dlsym(RTLD_DEFAULT, "nm_hex");
    g_tally  = (fn_tally) dlsym(RTLD_DEFAULT, "tl_tally");
    g_ihex   = (fn_ihex)  dlsym(RTLD_DEFAULT, "tl_hex");
    g_scan   = (fn_scan)  dlsym(RTLD_DEFAULT, "wr_scan");
}

static int kernel_missing(void) {
    return !(g_derive && g_seal && g_unseal && g_hex && g_tally && g_ihex && g_scan);
}

/* 拼装虚拟机输入缓冲：真标记(UTF-16 降 ASCII) ‖ salt。 */
static int build_input(uint8_t *in, int cap) {
    int p = 0;
    for (int i = 0; i < MK5_LEN && p < cap; i++) in[p++] = (uint8_t)(MK5[i] & 0xFF);
    for (const char *s = SALT; *s && p < cap; s++) in[p++] = (uint8_t)*s;
    return p;
}

static int hit_count(int bits) {
    int h = 0;
    for (int m = 1; m != 0 && m <= 16; m <<= 1) if (bits & m) h++;
    return h;
}

/* 派生主钥：跑虚拟机；命中 >= 2 项即翻位投毒（服务端恒 403）。 */
static int derive_seed(uint8_t seed[32]) {
    bind_kernels();
    if (kernel_missing()) return 0;
    int bits = 0;
    g_scan(&bits);
    uint8_t in[64];
    int in_len = build_input(in, sizeof(in));
    if (!g_derive(kKkl5VmProgram, KKL5_VM_PROGRAM_BYTES,
                  kKkl5VmStreamKey, KKL5_VM_STREAM_KEY_LEN,
                  kKkl5VmChainIV, KKL5_VM_CHAIN_IV_LEN,
                  in, in_len, seed, 32)) {
        g_poisoned = 1;
        return 0;
    }
    if (hit_count(bits) >= 2) {
        seed[7] ^= 0x40;                 /* 投毒：本地主钥与服务端不再一致 */
        g_poisoned = 1;
    }
    return 1;
}

static void iv_from_seed(const uint8_t seed[32], const char *tag, uint8_t out[16]) {
    /* md5(seed ‖ tag)[:16]；复用 tallow 的 tl_tally。 */
    uint8_t msg[64];
    int n = 32;
    memcpy(msg, seed, 32);
    for (const char *s = tag; *s; s++) msg[n++] = (uint8_t)*s;
    uint8_t dig[16];
    g_tally(msg, (size_t)n, dig);
    memcpy(out, dig, 16);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativeStatus(JNIEnv *env, jclass) {
    bind_kernels();
    char buf[680];
    if (kernel_missing()) {
        snprintf(buf, sizeof(buf),
                 "内核编队不完整：虚拟机 %s / 分组 %s / 摘要 %s / 守卫 %s\n"
                 "lib/ 下五个 so 缺一不可。",
                 g_derive ? "在位" : "缺失", g_seal ? "在位" : "缺失",
                 g_tally ? "在位" : "缺失", g_scan ? "在位" : "缺失");
        return env->NewStringUTF(buf);
    }
    int bits = 0;
    g_scan(&bits);
    snprintf(buf, sizeof(buf),
             "完整性自检（命中 %d 项，>=2 触发投毒）：\n"
             "  调试器痕迹 : %s\n"
             "  可写可执行段 : %s\n"
             "  断点痕迹   : %s\n"
             "  模拟器环境 : %s\n"
             "  自映射完整性 : %s\n"
             "  主钥状态   : %s\n"
             "  明文可见   : Fatdog_ascent（供比对）",
             hit_count(bits),
             (bits & 1) ? "命中" : "安全", (bits & 2) ? "命中" : "安全",
             (bits & 4) ? "命中" : "安全", (bits & 8) ? "命中" : "安全",
             (bits & 16) ? "命中" : "安全",
             g_poisoned ? "已污染（服务端将拒绝）" : "正常");
    return env->NewStringUTF(buf);
}

/* onCreate 抽取：门禁在虚拟机里跑，Java 侧只看结果。 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativeOnCreate(JNIEnv *env, jclass, jobject) {
    uint8_t seed[32];
    if (!derive_seed(seed)) {
        bind_kernels();
        return env->NewStringUTF(kernel_missing()
            ? "FAIL: 内核编队不完整" : "FAIL: 虚拟机未收敛");
    }
    return env->NewStringUTF("OK: onCreate 门禁通过（虚拟机已收敛）");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativeSign(JNIEnv *env, jclass, jint page, jlong ts) {
    uint8_t seed[32];
    if (!derive_seed(seed)) return env->NewStringUTF("");

    char payload[64];
    int pl = snprintf(payload, sizeof(payload), "page=%d&ts=%lld", (int)page, (long long)ts);

    uint8_t sm4_iv[16], aes_iv[16];
    iv_from_seed(seed, "|sm4", sm4_iv);
    iv_from_seed(seed, "|aes", aes_iv);

    uint8_t ct[256];
    int cl = g_seal(seed, sm4_iv, aes_iv, (const uint8_t *)payload, (size_t)pl, ct);
    if (cl <= 0) { g_poisoned = 1; return env->NewStringUTF(""); }
    char enc[600];
    g_hex(ct, (size_t)cl, enc);

    char kh[80];
    g_ihex(seed, 32, kh);
    char msg[700];
    snprintf(msg, sizeof(msg), "%s%s", kh, enc);
    uint8_t mac[16];
    g_tally((const uint8_t *)msg, strlen(msg), mac);
    char sign[40];
    g_ihex(mac, 16, sign);

    char out[680];
    snprintf(out, sizeof(out), "%s|%s", enc, sign);
    return env->NewStringUTF(out);
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativeUnseal(JNIEnv *env, jclass, jbyteArray sealed) {
    uint8_t seed[32];
    if (!derive_seed(seed)) return NULL;
    jsize n = env->GetArrayLength(sealed);
    if (n <= 16) return NULL;
    jbyte *in = env->GetByteArrayElements(sealed, NULL);
    if (!in) return NULL;
    uint8_t sm4_iv[16];
    iv_from_seed(seed, "|sm4", sm4_iv);
    uint8_t *out = (uint8_t *)malloc((size_t)n);
    int ol = out ? g_unseal(seed, sm4_iv, (const uint8_t *)in, (size_t)n, out) : -1;
    env->ReleaseByteArrayElements(sealed, in, JNI_ABORT);
    if (ol <= 0) { free(out); return NULL; }
    jbyteArray res = env->NewByteArray(ol);
    if (res) env->SetByteArrayRegion(res, 0, ol, (const jbyte *)out);
    free(out);
    return res;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Kkl5Native_nativePoisoned(JNIEnv *env, jclass) {
    (void)env;
    return g_poisoned ? 1 : 0;
}

/* 诱饵标记的出入口：保证 DECOY 进 .rodata，同时给静态分析留一条"假线索"。 */
extern "C" __attribute__((visibility("default"))) const char *kd_seal_tag(void) {
    return DECOY;
}
