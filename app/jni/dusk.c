/**
 * dusk.c — 扶桑树 KL26 暮霭沉沉
 *
 * 6 路信号 + 评分阈值制 + 加载期 (.init_array) 先跑。
 *
 *   ① timing 侧信道            —— 多轮采样，多数超阈值且中位数超限
 *   ② Frida 版本/特征嗅探      —— dlsym frida_* 符号 + maps frida/gadget 特征
 *   ③ 可执行段私有脏页         —— smaps 里 file-backed r-x 段 Private_Dirty 异常
 *   ④ 无名可执行映射(代码岛)   —— 无 VMA 名的 r-x 段（注入落点）
 *   ⑤ ARM64 跳板扫描           —— 代码岛内 LDR X16/17,[PC] / BR X16/17 成簇
 *   ⑥ libc 关键函数入口比对    —— 内存 vs 磁盘 libc.so 的 prologue 差异
 *
 *   命中数 >= KL26_THRESHOLD(2) 才判定检出 —— 评分阈值制，
 *   禁「任一命中即判」（沿用扶桑树评测铁律，防 ROM 误杀）。
 *
 * 【本关升级点 · 从"明文特征"走向"抓注入本身"】
 *   ① ② 是前几关的老路子（依赖明文特征串 / libc 接口）；③④⑤⑥ 是看雪 Sentry
 *   点名的「注入痕迹」检测——即使玩家把 frida 特征串全洗掉（strongR/Florida）、
 *   把 libc 的 open/read 换成假的，代码岛的脏页、跳板、libc 被改写的字节仍会露馅。
 *
 * 【加载期检测】
 *   so 被 System.loadLibrary 加载时，.init_array 里的 constructor 先跑一遍检测
 *   并缓存进 g_load_phase（0=未执行 / 1=加载期干净 / 2=加载期已命定）。
 *   nativeAnswer() 读缓存 —— 加载期一旦命中即永久锁定，事后 hook 运行期检测无效。
 *
 * SEED = 20280720
 * Flag: FLAG_18_KL26{dusk_hides_the_truth}
 */

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <dlfcn.h>
#include <sys/time.h>

#include "fuso_probe.h"

/* ============================================================
 * 诱饵标记：Fatdog_dusk（真）/ Fatdog_duks（假·少 s）
 * 仅作报告展示，不参与答案。
 * ============================================================ */
static const char REAL_MARK[] = "Fatdog_dusk";
static const char FAKE_MARK[] = "Fatdog_duks";

/* 评分阈值制：6 路信号里命中 >= 2 才判检出（验证时可 -DKL26_THRESHOLD=n 覆盖） */
#define KL26_SIG_COUNT 6
#ifndef KL26_THRESHOLD
#define KL26_THRESHOLD 2
#endif

/* 加载期相位 */
#define PHASE_UNRUN 0
#define PHASE_CLEAN 1
#define PHASE_HIT   2

/* ============================================================
 * 信号①：timing 侧信道（多轮采样 + 中位数去抖）
 * ============================================================ */
#define DUSK_TIMING_ROUNDS   9
#define DUSK_TIMING_MIN_SLOW 7
#define DUSK_TIMING_LIMIT_NS 500000L

static long dusk_timing_delta_ns(const struct timespec *a, const struct timespec *b) {
    return (b->tv_sec - a->tv_sec) * 1000000000L + (b->tv_nsec - a->tv_nsec);
}

static int dusk_cmp_long(const void *a, const void *b) {
    long x = *(const long *)a;
    long y = *(const long *)b;
    return (x > y) - (x < y);
}

static int detect_timing(void) {
    long samples[DUSK_TIMING_ROUNDS];
    int valid = 0;
    int slow = 0;

    /* 预热循环，避免首次调度的固定偏差进入样本。 */
    for (int round = 0; round < 2; round++) {
        volatile int dummy = 0;
        for (int i = 0; i < 1000; i++) dummy += i;
    }

    for (int round = 0; round < DUSK_TIMING_ROUNDS; round++) {
        struct timespec t1, t2;
        volatile int dummy = 0;

        clock_gettime(CLOCK_MONOTONIC, &t1);
        for (int i = 0; i < 1000; i++) dummy += i;
        clock_gettime(CLOCK_MONOTONIC, &t2);

        long elapsed_ns = dusk_timing_delta_ns(&t1, &t2);
        samples[valid++] = elapsed_ns;
        if (elapsed_ns > DUSK_TIMING_LIMIT_NS) slow++;
    }

    if (valid < DUSK_TIMING_MIN_SLOW || slow < DUSK_TIMING_MIN_SLOW) return 0;
    qsort(samples, valid, sizeof(long), dusk_cmp_long);
    return samples[valid / 2] > DUSK_TIMING_LIMIT_NS;
}

/* ============================================================
 * 信号②：Frida 版本/特征嗅探
 * ============================================================ */
static int detect_frida_version(void) {
    void *handle = dlopen(NULL, RTLD_NOW);
    if (handle) {
        const char *symbols[] = {
            "frida_agent_main",
            "frida_uspawn_client",
            "frida_log",
            "_frida_backtrace",
            NULL
        };
        for (int i = 0; symbols[i]; i++) {
            if (dlsym(handle, symbols[i])) {
                dlclose(handle);
                return 1;
            }
        }
        dlclose(handle);
    }

    FILE *f = fopen("/proc/self/maps", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "frida") || strstr(line, "gadget")) {
                fclose(f);
                return 1;
            }
        }
        fclose(f);
    }
    return 0;
}

/* ============================================================
 * 信号③④⑤⑥：注入痕迹层（实现见 fuso_probe.h）
 *   ③ fuso_smaps_dirty() / ④ fuso_anon_exec() /
 *   ⑤ fuso_trampoline()  / ⑥ fuso_libc_prologue()
 * ============================================================ */

/* ============================================================
 * 评分：返回命中信号数（0..KL26_SIG_COUNT）
 * ============================================================ */
static int detect_score(void) {
    int s = 0;
    s += detect_timing();
    s += detect_frida_version();
    s += fuso_smaps_dirty();
    s += fuso_anon_exec();
    s += fuso_trampoline();
    s += fuso_libc_prologue();
    return s;
}

/* ============================================================
 * 加载期检测缓存（.init_array 阶段写入）
 * ============================================================ */
static volatile int g_load_phase = PHASE_UNRUN;
static volatile int g_load_score = 0;

/* constructor(101)：优先级 101 为可用最小值，确保在其它构造前先跑 */
__attribute__((constructor(101)))
static void _dusk_load_guard(void) {
    int s = detect_score();
    g_load_score = s;
    g_load_phase = (s >= KL26_THRESHOLD) ? PHASE_HIT : PHASE_CLEAN;
}

/* ============================================================
 * 综合检测（评分阈值制 + 加载期锁定）
 * ============================================================ */
static int detect_frida(void) {
    if (g_load_phase == PHASE_HIT) return 1;   /* 加载期已判定命中 → 永久锁定 */
    return detect_score() >= KL26_THRESHOLD;
}

/* ============================================================
 * 答案计算：基于 SEED 的确定性哈希
 *   检出 → 固定锁定串（提交必败）；未检出 → 真答案。
 * ============================================================ */
static const char* compute_answer(void) {
    static char result[33];
    if (detect_frida()) return "DETECTED_FRIDA_LOCKED_ANSWER";
    unsigned int seed = 20280720;
    unsigned int hash = seed;
    hash = hash * 1103515245u + 12345u;
    hash ^= hash << 13;
    hash ^= hash >> 17;
    hash ^= hash << 5;
    unsigned int h2 = seed;
    h2 = h2 * 214013u + 2531011u;
    hash ^= h2;
    for (int i = 0; i < 32; i++) {
        result[i] = "0123456789abcdef"[(hash >> (i % 4 * 4)) & 0xf];
        hash = hash * 1664525u + 1013904223u;
    }
    result[32] = '\0';
    return result;
}

/* ============================================================
 * 状态详情
 * ============================================================ */
static const char* load_phase_str(void) {
    switch (g_load_phase) {
        case PHASE_HIT:   return "已命中(2)";
        case PHASE_CLEAN: return "干净(1)";
        default:          return "未执行(0)";
    }
}

static const char* compute_status(void) {
    static char buf[1400];
    int timing = detect_timing();
    int version = detect_frida_version();
    int dirty = fuso_smaps_dirty();
    int anon = fuso_anon_exec();
    int tramp = fuso_trampoline();
    int libc = fuso_libc_prologue();
    int sc = detect_score();

    snprintf(buf, sizeof(buf),
        "=== 暮霭沉沉（6 路评分阈值制 · 加载期先跑）===\n"
        "加载期相位(.init_array): %s   加载期命中数: %d\n"
        "--------------------------------------------------\n"
        "① timing 侧信道    : %-4s\n"
        "② 版本/特征嗅探    : %-4s\n"
        "③ 可执行段私有脏页 : %-4s\n"
        "④ 无名可执行代码岛 : %-4s\n"
        "⑤ ARM64 跳板扫描   : %-4s\n"
        "⑥ libc 入口比对    : %-4s\n"
        "--------------------------------------------------\n"
        "命中 %d/%d 路，阈值 >= %d 判检出\n"
        "综合判定: %s\n\n"
        "标记A: %s\n标记B: %s",
        load_phase_str(), g_load_score,
        timing ? "命中" : "安全",
        version ? "命中" : "安全",
        dirty ? "命中" : "安全",
        anon ? "命中" : "安全",
        tramp ? "命中" : "安全",
        libc ? "命中" : "安全",
        sc, KL26_SIG_COUNT, KL26_THRESHOLD,
        detect_frida() ? "检出" : "安全",
        REAL_MARK, FAKE_MARK);
    return buf;
}

/* ============================================================
 * JNI 导出
 * ============================================================ */

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Sk_nativeTiming(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return detect_timing();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Sk_nativeVersion(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return detect_frida_version();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Sk_nativeSmapsDirty(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return fuso_smaps_dirty();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Sk_nativeAnonExec(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return fuso_anon_exec();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Sk_nativeTrampoline(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return fuso_trampoline();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Sk_nativeLibcPrologue(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return fuso_libc_prologue();
}

/* 加载期相位：0=未执行 1=加载期干净 2=加载期已命中 */
JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Sk_nativeLoadPhase(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return (jint)g_load_phase;
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Sk_nativeFridaDetect(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return detect_frida();
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Sk_nativeAnswer(JNIEnv *e, jclass c) {
    (void)c;
    return (*e)->NewStringUTF(e, compute_answer());
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Sk_nativeStatus(JNIEnv *e, jclass c) {
    (void)c;
    return (*e)->NewStringUTF(e, compute_status());
}
