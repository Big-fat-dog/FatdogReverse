/* 自动生成：python gen_kkl4.py —— 请勿手改。 */
/* 太玄之初 KKL4 锁妖塔 · 五 so 编队（门面/虚拟机/分组/摘要/守卫）。 */

/*
 * citadel —— 太玄之初 KKL4 锁妖塔的 JNI 门面。
 *
 * 本 so 是全关**唯一**导出 Java_ 符号的库；它自身不含任何算法，
 * 全部内核靠 dlsym(RTLD_DEFAULT) 从其它四个 so 取：
 *     ob_vm_seed   （obsidian）栈式虚拟机派生主钥（32B）
 *     cv_seal/cv_hex（cavern）AES-128-CTR 与十六进制
 *     td_tally/td_hex（tundra）MD5 摘要
 *     pw_scan      （prowl）  完整性守卫
 * 缺任一内核 → 自检报"内核缺失"，签名返回空串。
 *
 * 真标记以 UTF-16 码元藏在本文件的 .data（MK4[]），运行时逐字降 ASCII 后
 * 与 salt 拼成输入缓冲喂给虚拟机——标记**不进入字节码**，字节码里只有取数下标。
 */
#include <jni.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kkl4_vm_program.h"

typedef bool (*fn_vm_seed)(const uint8_t *, size_t, const uint8_t *, size_t,
                           const uint8_t *, size_t, uint8_t *, int);
typedef int  (*fn_seal)(const uint8_t *, const uint8_t *, const uint8_t *, size_t, uint8_t *);
typedef void (*fn_hex)(const uint8_t *, size_t, char *);
typedef void (*fn_tally)(const uint8_t *, size_t, uint8_t *);
typedef void (*fn_ihex)(const uint8_t *, int, char *);
typedef int  (*fn_scan)(int *);

static fn_vm_seed g_vm = NULL;
static fn_seal    g_seal = NULL;
static fn_hex     g_hex = NULL;
static fn_tally   g_tally = NULL;
static fn_ihex    g_ihex = NULL;
static fn_scan    g_scan = NULL;

static volatile int g_poisoned = 0;
static volatile int g_last_bits = 0;

/* ================= 真标记：UTF-16 藏匿（const volatile 保证不被折叠成立即数） ================= */
static const volatile jchar MK4[] = { 0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067, 0x005F, 0x0064, 0x0072, 0x0065, 0x0061, 0x0064 };
#define MK4_LEN ((int)(sizeof(MK4) / sizeof(jchar)))

/* 明文诱饵：与真标记仅末位一字之差（d/m），由 kd_seal_tag() 引用，保证进 .rodata */
static const char DECOY[] = "Fatdog_dream";
static const char SALT[]  = "|kkl4_tower";

static void bind_kernels(void) {
    if (g_vm) return;
    g_vm    = (fn_vm_seed)dlsym(RTLD_DEFAULT, "ob_vm_seed");
    g_seal  = (fn_seal)   dlsym(RTLD_DEFAULT, "cv_seal");
    g_hex   = (fn_hex)    dlsym(RTLD_DEFAULT, "cv_hex");
    g_tally = (fn_tally)  dlsym(RTLD_DEFAULT, "td_tally");
    g_ihex  = (fn_ihex)   dlsym(RTLD_DEFAULT, "td_hex");
    g_scan  = (fn_scan)   dlsym(RTLD_DEFAULT, "pw_scan");
}

static int kernel_missing(void) {
    return !(g_vm && g_seal && g_hex && g_tally && g_ihex && g_scan);
}

/* 拼装虚拟机输入缓冲：真标记(UTF-16 降 ASCII) ‖ salt。 */
static int build_input(uint8_t *in, int cap) {
    int p = 0;
    for (int i = 0; i < MK4_LEN && p < cap; i++) in[p++] = (uint8_t)(MK4[i] & 0xFF);
    for (const char *s = SALT; *s && p < cap; s++) in[p++] = (uint8_t)*s;
    return p;
}

/* 翻位投毒：让本地派生出的主钥与服务端不再一致（服务端恒 403）。 */
static void poison(uint8_t *seed) {
    if (g_poisoned) return;
    seed[7] ^= 0x40;
    g_poisoned = 1;
}

static int hit_count(int bits) {
    int h = 0;
    for (int m = 1; m != 0 && m <= 16; m <<= 1) if (bits & m) h++;
    return h;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl4Native_nativeStatus(JNIEnv *env, jclass) {
    bind_kernels();
    char buf[640];
    if (kernel_missing()) {
        snprintf(buf, sizeof(buf),
                 "内核编队不完整：虚拟机 %s / 分组 %s / 摘要 %s / 守卫 %s\n"
                 "lib/ 下五个 so 缺一不可。",
                 g_vm ? "在位" : "缺失", g_seal ? "在位" : "缺失",
                 g_tally ? "在位" : "缺失", g_scan ? "在位" : "缺失");
        return env->NewStringUTF(buf);
    }
    int bits = 0;
    g_scan(&bits);
    g_last_bits = bits;
    snprintf(buf, sizeof(buf),
             "完整性自检（命中 %d 项，>=2 触发投毒）：\n"
             "  调试器痕迹 : %s\n"
             "  可写可执行段 : %s\n"
             "  断点痕迹   : %s\n"
             "  模拟器环境 : %s\n"
             "  自映射完整性 : %s\n"
             "  主钥状态   : %s\n"
             "  明文可见   : Fatdog_dream（供比对）",
             hit_count(bits),
             (bits & 1) ? "命中" : "安全", (bits & 2) ? "命中" : "安全",
             (bits & 4) ? "命中" : "安全", (bits & 8) ? "命中" : "安全",
             (bits & 16) ? "命中" : "安全",
             g_poisoned ? "已污染（服务端将拒绝）" : "正常");
    return env->NewStringUTF(buf);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl4Native_nativeSign(JNIEnv *env, jclass, jint page, jlong ts) {
    bind_kernels();
    if (kernel_missing()) return env->NewStringUTF("");
    int bits = 0;
    g_scan(&bits);
    g_last_bits = bits;

    uint8_t in[64];
    int in_len = build_input(in, sizeof(in));

    uint8_t seed[32];
    if (!g_vm(kKkl4VmProgram, KKL4_VM_PROGRAM_BYTES,
              kKkl4VmChainSeed, KKL4_VM_CHAIN_SEED_LEN,
              in, in_len, seed, 32)) {
        g_poisoned = 1;
        return env->NewStringUTF("");
    }
    if (hit_count(bits) >= 2) poison(seed);

    char payload[64];
    int pl = snprintf(payload, sizeof(payload), "page=%d&ts=%lld", (int)page, (long long)ts);

    uint8_t ct[128];
    int cl = g_seal(seed, seed + 16, (const uint8_t *)payload, (size_t)pl, ct);
    if (cl <= 0) { g_poisoned = 1; return env->NewStringUTF(""); }
    char enc[300];
    g_hex(ct, (size_t)cl, enc);

    char kh[80];
    g_ihex(seed, 32, kh);
    char msg[420];
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
Java_com_fatdog_reverse_Kkl4Native_nativePoisoned(JNIEnv *env, jclass) {
    (void)env;
    return g_poisoned ? 1 : 0;
}

/* 诱饵标记的出入口：保证 DECOY 进 .rodata，同时给静态分析留一条"假线索"。 */
extern "C" __attribute__((visibility("default"))) const char *kd_seal_tag(void) {
    return DECOY;
}
