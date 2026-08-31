/**
 * dusk.c — 扶桑树 KL26 暮霭沉沉
 * 双重检测：timing side-channel + Frida 版本字符串嗅探
 * 判定逻辑：XOR（奇数路触发才判定）
 * SEED = 20280720
 * Flag: FLAG_18_KL26{dusk_hides_the_truth}
 */

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <dlfcn.h>
#include <sys/time.h>

/* ============================================================
 * 诱饵标记：Fatdog_dusk（真）/ Fatdog_dusk（假·少 s）
 * ============================================================ */
static const char REAL_MARK[]  = "Fatdog_dusk";
static const char FAKE_MARK[]  = "Fatdog_duks";

/* ============================================================
 * 检测①：timing side-channel（fork+clock 测量反调试延迟）
 * ============================================================ */
static int detect_timing(void) {
    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    /* 轻量操作：如果存在 frida hook，这会比预期慢 */
    volatile int dummy = 0;
    for (int i = 0; i < 1000; i++) {
        dummy += i;
    }

    clock_gettime(CLOCK_MONOTONIC, &t2);

    long elapsed_ns = (t2.tv_sec - t1.tv_sec) * 1000000000L + (t2.tv_nsec - t1.tv_nsec);

    /* 正常应该 < 100000ns (100us)，hook 会导致显著延迟 */
    return elapsed_ns > 500000;  /* 500us 阈值 */
}

/* ============================================================
 * 检测②：Frida 版本字符串嗅探
 * ============================================================ */
static int detect_frida_version(void) {
    /* 尝试通过 dlsym 查找 Frida 特有符号 */
    void *handle = dlopen(NULL, RTLD_NOW);
    if (handle) {
        /* Frida 注入的典型符号 */
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

    /* 检查 /proc/self/maps 中的 frida 特征 */
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
 * 综合检测（XOR 判定：奇数路触发才判定）
 * ============================================================ */
static int detect_frida(void) {
    int timing = detect_timing();
    int version = detect_frida_version();

    /* XOR：只有奇数路触发才判定 */
    return timing ^ version;
}

/* ============================================================
 * 答案计算
 * ============================================================ */
static const char* compute_answer(void) {
    static char result[33];
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
static const char* compute_status(void) {
    static char buf[512];
    int timing = detect_timing();
    int version = detect_frida_version();

    snprintf(buf, sizeof(buf),
        "=== 暮霭沉沉 ===\n"
        "timing检测:     %s\n"
        "版本嗅探:       %s\n"
        "综合判定(XOR):  %s\n\n"
        "标记A: %s\n标记B: %s",
        timing ? "检出" : "安全",
        version ? "检出" : "安全",
        detect_frida() ? "检出" : "安全",
        REAL_MARK, FAKE_MARK);
    return buf;
}

/* ============================================================
 * JNI 导出
 * ============================================================ */

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Sk_nativeTiming(JNIEnv *e, jclass c) {
    return detect_timing();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Sk_nativeVersion(JNIEnv *e, jclass c) {
    return detect_frida_version();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Sk_nativeFridaDetect(JNIEnv *e, jclass c) {
    return detect_frida();
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Sk_nativeAnswer(JNIEnv *e, jclass c) {
    return (*e)->NewStringUTF(e, compute_answer());
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Sk_nativeStatus(JNIEnv *e, jclass c) {
    return (*e)->NewStringUTF(e, compute_status());
}
