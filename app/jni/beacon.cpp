/* 自动生成：python gen_kkl3.py —— 请勿手改。 */
/* 太玄之初 KKL3 断魂谷 · 五 so 编队（门面/虚拟机/国密/摘要/守卫）。 */

/*
 * beacon —— 太玄之初 KKL3 断魂谷的 JNI 门面。
 *
 * 本 so 是全关**唯一**导出 Java_ 符号的库；它自身不含任何算法，
 * 全部内核靠 dlsym(RTLD_DEFAULT) 从其它四个 so 取：
 *     lt_vm_seed  （lattice）  虚拟机派生主钥
 *     bs_seal/bs_hex（basalt）国密 SM4-ECB 与十六进制
 *     ig_tally    （ingot）    MD5 摘要
 *     hb_scan     （harbor）   完整性守卫
 * 缺任一内核 → 自检报"内核缺失"，签名返回空串。
 */
#include <jni.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>

#include "kkl3_vm_program.h"

typedef bool (*fn_vm_seed)(const uint8_t *, size_t, const uint8_t *, size_t, int, uint8_t *, int);
typedef int  (*fn_seal)(const uint8_t *, const uint8_t *, size_t, uint8_t *);
typedef int  (*fn_unseal)(const uint8_t *, const uint8_t *, size_t, uint8_t *);
typedef void (*fn_hex)(const uint8_t *, size_t, char *);
typedef void (*fn_tally)(const uint8_t *, size_t, uint8_t *);
typedef void (*fn_ihex)(const uint8_t *, int, char *);
typedef int  (*fn_scan)(int *);

static fn_vm_seed g_vm = NULL;
static fn_seal    g_seal = NULL;
static fn_unseal  g_unseal = NULL;
static fn_hex     g_hex = NULL;
static fn_tally   g_tally = NULL;
static fn_ihex    g_ihex = NULL;
static fn_scan    g_scan = NULL;

static volatile int g_poisoned = 0;
static volatile int g_last_bits = 0;

static void bind_kernels(void) {
    if (g_vm) return;
    g_vm     = (fn_vm_seed)dlsym(RTLD_DEFAULT, "lt_vm_seed");
    g_seal   = (fn_seal)   dlsym(RTLD_DEFAULT, "bs_seal");
    g_unseal = (fn_unseal) dlsym(RTLD_DEFAULT, "bs_unseal");
    g_hex    = (fn_hex)    dlsym(RTLD_DEFAULT, "bs_hex");
    g_tally  = (fn_tally)  dlsym(RTLD_DEFAULT, "ig_tally");
    g_ihex   = (fn_ihex)   dlsym(RTLD_DEFAULT, "ig_hex");
    g_scan   = (fn_scan)   dlsym(RTLD_DEFAULT, "hb_scan");
}

static int kernel_missing(void) {
    return !(g_vm && g_seal && g_hex && g_tally && g_ihex && g_scan);
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
                 "内核编队不完整：虚拟机 %s / 国密 %s / 摘要 %s / 守卫 %s\n"
                 "lib/ 下五个 so 缺一不可。",
                 g_vm ? "在位" : "缺失", g_seal ? "在位" : "缺失",
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
Java_com_fatdog_reverse_Kkl3Native_nativeSign(JNIEnv *env, jclass, jint page, jlong ts) {
    bind_kernels();
    if (kernel_missing()) return env->NewStringUTF("");
    int bits = 0;
    g_scan(&bits);
    g_last_bits = bits;
    int hit = ((bits & 1) ? 1 : 0) + ((bits & 2) ? 1 : 0) + ((bits & 4) ? 1 : 0) + ((bits & 8) ? 1 : 0);

    uint8_t seed[16];
    if (!g_vm(kKkl3VmProgramEnc, sizeof(kKkl3VmProgramEnc),
              kKkl3VmRollingSeed, KKL3_VM_SEED_LEN, 1, seed, 16)) {
        g_poisoned = 1;
        return env->NewStringUTF("");
    }
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
