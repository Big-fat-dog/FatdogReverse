/**
 * veil.c — 扶桑树 KL27 轻纱覆影
 * 双重检测：Frida 线程上下文指纹 + 时序指纹交叉验证
 * 判定逻辑：OR（任一触发即判定）
 * SEED = 20280721
 * Flag: FLAG_18_KL27{veil_conceals_all}
 */

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <dirent.h>
#include <dlfcn.h>

/* ============================================================
 * 诱饵标记：Fatdog_gauze（真）/ Fatdog_gauz（假·少 e）
 * ============================================================ */
static const char REAL_MARK[]  = "Fatdog_gauze";
static const char FAKE_MARK[]  = "Fatdog_gauz";

/* ============================================================
 * 检测①：Frida 线程上下文指纹
 * ============================================================ */
static int detect_thread_context(void) {
    /* 检查 Frida 的典型线程特征 */
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", getpid());

    DIR *dir = opendir(path);
    if (!dir) return 0;

    int frida_threads = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char thread_path[128];
        snprintf(thread_path, sizeof(thread_path), "/proc/%d/task/%s/status",
                 getpid(), ent->d_name);

        FILE *f = fopen(thread_path, "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "frida") || strstr(line, "gmain")) {
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
 * 检测②：时序指纹交叉验证（多轮采样 + 中位数去抖）
 * ============================================================ */
#define TIMING_ROUNDS      9
#define TIMING_MIN_SLOW    7
#define TIMING_ABS_NS      1000000L
#define TIMING_RATIO       100L

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

    /* 预热动态加载器，排除首次加载造成的固定偏差。 */
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
 * 综合检测（OR 判定）
 * ============================================================ */
static int detect_frida(void) {
    return detect_thread_context() || detect_timing_crossref();
}

/* ============================================================
 * 答案计算
 * ============================================================ */
static const char* compute_answer(void) {
    static char result[33];
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
static const char* compute_status(void) {
    static char buf[512];
    int thread = detect_thread_context();
    int timing = detect_timing_crossref();

    snprintf(buf, sizeof(buf),
        "=== 轻纱覆影 ===\n"
        "线程指纹:       %s\n"
        "时序交叉:       %s\n"
        "综合判定(OR):   %s\n\n"
        "标记A: %s\n标记B: %s",
        thread ? "检出" : "安全",
        timing ? "检出" : "安全",
        detect_frida() ? "检出" : "安全",
        REAL_MARK, FAKE_MARK);
    return buf;
}

/* ============================================================
 * JNI 导出
 * ============================================================ */

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Vk27_nativeThreadContext(JNIEnv *e, jclass c) {
    return detect_thread_context();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Vk27_nativeTimingCrossref(JNIEnv *e, jclass c) {
    return detect_timing_crossref();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Vk27_nativeFridaDetect(JNIEnv *e, jclass c) {
    return detect_frida();
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Vk27_nativeAnswer(JNIEnv *e, jclass c) {
    return (*e)->NewStringUTF(e, compute_answer());
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Vk27_nativeStatus(JNIEnv *e, jclass c) {
    return (*e)->NewStringUTF(e, compute_status());
}
