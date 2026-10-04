/**
 * veil.c — 扶桑树 KL27 轻纱覆影
 *
 * 7 路信号 + 评分阈值制 + 加载期 (.init_array) 先跑。
 *
 *   ① 线程上下文指纹           —— /proc/<pid>/task/<tid>/status 命中 frida 线程名
 *   ② 时序交叉验证             —— dlopen 与 malloc 延迟比，多轮中位数去抖
 *   ③ 可执行段私有脏页         —— smaps 里 file-backed r-x 段 Private_Dirty 异常
 *   ④ 无名可执行映射(代码岛)   —— 无 VMA 名的 r-x 段（注入落点）
 *   ⑤ ARM64 跳板扫描           —— 代码岛内 LDR X16/17,[PC] / BR X16/17 成簇
 *   ⑥ libc 关键函数入口比对    —— 内存 vs 磁盘 libc.so 的 prologue 差异
 *   ⑦ libc 代码段采样校验      —— 段内多点窗口 内存 vs 磁盘，抓非入口补丁
 *
 *   命中数 >= KL27_THRESHOLD(2) 才判定检出 —— 评分阈值制。
 *
 * 【本关升级点 · 比 KL26 更深的「注入痕迹」】
 *   ③④⑤ 面向「代码岛」；⑥ 抓函数入口的 inline hook；⑦ 再往深一层，覆盖 libc
 *   代码段内部任意位置的改写（⑥ 看不到的非入口补丁）。相对 KL26 多一路信号，
 *   且 ⑦ 的覆盖面比 ⑥ 广——难度与监测点均递增。
 *
 * 【加载期检测】
 *   so 加载时 .init_array 先跑一遍并缓存相位（0=未执行 / 1=干净 / 2=命中）；
 *   nativeAnswer() 读缓存 —— 加载期一旦命中即永久锁定，事后 hook 运行期检测无效。
 *
 * SEED = 20280721
 * Flag: FLAG_18_KL27{veil_conceals_all}
 */

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <dirent.h>
#include <dlfcn.h>

#include "fuso_probe.h"

/* ============================================================
 * 诱饵标记：Fatdog_gauze（真）/ Fatdog_gauz（假·少 e）
 * ============================================================ */
static const char REAL_MARK[] = "Fatdog_gauze";
static const char FAKE_MARK[] = "Fatdog_gauz";

/* 评分阈值制：7 路信号里命中 >= 2 才判检出（验证时可 -DKL27_THRESHOLD=n 覆盖） */
#define KL27_SIG_COUNT 7
#ifndef KL27_THRESHOLD
#define KL27_THRESHOLD 2
#endif

/* 加载期相位 */
#define PHASE_UNRUN 0
#define PHASE_CLEAN 1
#define PHASE_HIT   2

/* ============================================================
 * 信号①：Frida 线程上下文指纹
 * ============================================================ */
static int detect_thread_context(void) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", getpid());

    DIR *dir = opendir(path);
    if (!dir) return 0;

    int frida_threads = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char thread_path[320];
        snprintf(thread_path, sizeof(thread_path), "/proc/%d/task/%s/status",
                 getpid(), ent->d_name);

        FILE *f = fopen(thread_path, "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "frida") || strstr(line, "gum-js-loop") ||
                    strstr(line, "pool-frida") || strstr(line, "linjector")) {
                    frida_threads++;
                    break;
                }
            }
            fclose(f);
        }
    }
    closedir(dir);

    return frida_threads > 0;
}

/* ============================================================
 * 信号②：时序指纹交叉验证（多轮采样 + 中位数去抖）
 * ============================================================ */
#define TIMING_ROUNDS    9
#define TIMING_MIN_SLOW  7
#define TIMING_ABS_NS    1000000L
#define TIMING_RATIO     100L

static long timing_delta_ns(const struct timespec *a, const struct timespec *b) {
    return (b->tv_sec - a->tv_sec) * 1000000000L + (b->tv_nsec - a->tv_nsec);
}

static int cmp_long(const void *a, const void *b) {
    long x = *(const long *)a;
    long y = *(const long *)b;
    return (x > y) - (x < y);
}

static int detect_timing_crossref(void) {
    long dl_samples[TIMING_ROUNDS];
    long mem_samples[TIMING_ROUNDS];
    int valid = 0;
    int slow = 0;

    /* 预热动态加载器与分配器，排除首次调用的固定偏差。 */
    for (int i = 0; i < 2; i++) {
        void *h = dlopen("liblog.so", RTLD_NOW);
        if (h) dlclose(h);
        void *p = malloc(256);
        free(p);
    }

    for (int i = 0; i < TIMING_ROUNDS; i++) {
        struct timespec t1, t2, t3, t4;

        clock_gettime(CLOCK_MONOTONIC, &t1);
        void *h = dlopen("liblog.so", RTLD_NOW);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        if (!h) continue;
        dlclose(h);

        clock_gettime(CLOCK_MONOTONIC, &t3);
        void *p = malloc(1024);
        clock_gettime(CLOCK_MONOTONIC, &t4);
        free(p);

        long dl_ns = timing_delta_ns(&t1, &t2);
        long mem_ns = timing_delta_ns(&t3, &t4);
        dl_samples[valid] = dl_ns;
        mem_samples[valid] = mem_ns;
        if (dl_ns > TIMING_ABS_NS && dl_ns / (mem_ns + 1) > TIMING_RATIO) slow++;
        valid++;
    }

    if (valid < TIMING_MIN_SLOW) return 0;
    qsort(dl_samples, valid, sizeof(long), cmp_long);
    qsort(mem_samples, valid, sizeof(long), cmp_long);
    long dl_median = dl_samples[valid / 2];
    long mem_median = mem_samples[valid / 2];
    if (dl_median <= TIMING_ABS_NS) return 0;
    if (dl_median / (mem_median + 1) <= TIMING_RATIO) return 0;
    return slow >= TIMING_MIN_SLOW;
}

/* ============================================================
 * 信号③④⑤⑥⑦：注入痕迹层（实现见 fuso_probe.h）
 *   ③ fuso_smaps_dirty() / ④ fuso_anon_exec() / ⑤ fuso_trampoline()
 *   ⑥ fuso_libc_prologue() / ⑦ fuso_libc_scan()
 * ============================================================ */

/* ============================================================
 * 评分：返回命中信号数（0..KL27_SIG_COUNT）
 * ============================================================ */
static int detect_score(void) {
    int s = 0;
    s += detect_thread_context();
    s += detect_timing_crossref();
    s += fuso_smaps_dirty();
    s += fuso_anon_exec();
    s += fuso_trampoline();
    s += fuso_libc_prologue();
    s += fuso_libc_scan();
    return s;
}

/* ============================================================
 * 加载期检测缓存（.init_array 阶段写入）
 * ============================================================ */
static volatile int g_load_phase = PHASE_UNRUN;
static volatile int g_load_score = 0;

__attribute__((constructor(101)))
static void _veil_load_guard(void) {
    int s = detect_score();
    g_load_score = s;
    g_load_phase = (s >= KL27_THRESHOLD) ? PHASE_HIT : PHASE_CLEAN;
}

/* ============================================================
 * 综合检测（评分阈值制 + 加载期锁定）
 * ============================================================ */
static int detect_frida(void) {
    if (g_load_phase == PHASE_HIT) return 1;
    return detect_score() >= KL27_THRESHOLD;
}

/* ============================================================
 * 答案计算
 * ============================================================ */
static const char* compute_answer(void) {
    static char result[33];
    if (detect_frida()) return "DETECTED_FRIDA_LOCKED_ANSWER";
    unsigned int seed = 20280721;
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
    static char buf[1500];
    int thread = detect_thread_context();
    int timing = detect_timing_crossref();
    int dirty = fuso_smaps_dirty();
    int anon = fuso_anon_exec();
    int tramp = fuso_trampoline();
    int libc = fuso_libc_prologue();
    int scan = fuso_libc_scan();
    int sc = detect_score();

    snprintf(buf, sizeof(buf),
        "=== 轻纱覆影（7 路评分阈值制 · 加载期先跑）===\n"
        "加载期相位(.init_array): %s   加载期命中数: %d\n"
        "--------------------------------------------------\n"
        "① 线程上下文指纹   : %-4s\n"
        "② 时序交叉验证     : %-4s\n"
        "③ 可执行段私有脏页 : %-4s\n"
        "④ 无名可执行代码岛 : %-4s\n"
        "⑤ ARM64 跳板扫描   : %-4s\n"
        "⑥ libc 入口比对    : %-4s\n"
        "⑦ libc 段采样校验  : %-4s\n"
        "--------------------------------------------------\n"
        "命中 %d/%d 路，阈值 >= %d 判检出\n"
        "综合判定: %s\n\n"
        "标记A: %s\n标记B: %s",
        load_phase_str(), g_load_score,
        thread ? "命中" : "安全",
        timing ? "命中" : "安全",
        dirty ? "命中" : "安全",
        anon ? "命中" : "安全",
        tramp ? "命中" : "安全",
        libc ? "命中" : "安全",
        scan ? "命中" : "安全",
        sc, KL27_SIG_COUNT, KL27_THRESHOLD,
        detect_frida() ? "检出" : "安全",
        REAL_MARK, FAKE_MARK);
    return buf;
}

/* ============================================================
 * JNI 导出
 * ============================================================ */

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Vk27_nativeThreadContext(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return detect_thread_context();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Vk27_nativeTimingCrossref(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return detect_timing_crossref();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Vk27_nativeSmapsDirty(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return fuso_smaps_dirty();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Vk27_nativeAnonExec(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return fuso_anon_exec();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Vk27_nativeTrampoline(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return fuso_trampoline();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Vk27_nativeLibcPrologue(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return fuso_libc_prologue();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Vk27_nativeLibcScan(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return fuso_libc_scan();
}

/* 加载期相位：0=未执行 1=加载期干净 2=加载期已命中 */
JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Vk27_nativeLoadPhase(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return (jint)g_load_phase;
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Vk27_nativeFridaDetect(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return detect_frida();
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Vk27_nativeAnswer(JNIEnv *e, jclass c) {
    (void)c;
    return (*e)->NewStringUTF(e, compute_answer());
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Vk27_nativeStatus(JNIEnv *e, jclass c) {
    (void)c;
    return (*e)->NewStringUTF(e, compute_status());
}
