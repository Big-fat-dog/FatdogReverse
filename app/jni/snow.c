/**
 * snow.c — 扶桑树 KL28 雪落无痕
 * 双重检测：Signal handler 注册 + TracerPid 追踪检查
 * 判定逻辑：OR（任一触发即判定）
 * SEED = 20280722
 * Flag: FLAG_18_KL28{snow_leaves_no_trace}
 */

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

/* ============================================================
 * 诱饵标记：Fatdog_snow（真）/ Fatdog_snow（假·少 n）
 * ============================================================ */
static const char REAL_MARK[]  = "Fatdog_snow";
static const char FAKE_MARK[]  = "Fatdog_sow";

/* ============================================================
 * 检测①：Signal handler 自我识别（可靠版，避免误报）
 * 思路：
 *   1) 先查询 SIGUSR1 是否已被他人（如 frida）预装自定义 handler；
 *   2) 再自行安装并验证可正常触发，且解除本线程屏蔽避免信号被阻塞。
 *   仅当“已被他人劫持”或“自身 handler 确实无法触发”时才判检出。
 * ============================================================ */
static volatile int sigusr1_count = 0;

static void sigusr1_handler(int sig) {
    (void)sig;
    sigusr1_count++;
}

static int detect_signal_handler(void) {
    struct sigaction old;
    memset(&old, 0, sizeof(old));
    sigaction(SIGUSR1, NULL, &old);

    /* 1) 已被他人安装自定义 handler（非默认/忽略）→ 疑似被注入 */
    if (old.sa_handler != SIG_DFL && old.sa_handler != SIG_IGN) {
        return 1;
    }

    /* 2) 自行安装并验证可触发（解除本线程 SIGUSR1 屏蔽，避免信号被阻塞误判） */
    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigprocmask(SIG_UNBLOCK, &mask, &oldmask);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigusr1_handler;
    sigaction(SIGUSR1, &sa, NULL);

    sigusr1_count = 0;
    kill(getpid(), SIGUSR1);

    /* 轮询等待 handler 执行（最多约 10ms），消除 1ms 竞态误报 */
    struct timespec ts = {0, 200000}; /* 0.2ms */
    for (int i = 0; i < 50 && sigusr1_count == 0; i++) {
        nanosleep(&ts, NULL);
    }

    /* 还原原有 disposition 与信号屏蔽字 */
    sigaction(SIGUSR1, &old, NULL);
    sigprocmask(SIG_SETMASK, &oldmask, NULL);

    /* 自身 handler 仍未能触发 → 信号被拦截/屏蔽，可疑 */
    return sigusr1_count == 0 ? 1 : 0;
}

/* ============================================================
 * 检测②：TracerPid 追踪检查
 * ============================================================ */
static int detect_ptrace(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    int tracer_pid = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer_pid = atoi(line + 10);
            break;
        }
    }
    fclose(f);

    /* 仅真实存在的 tracer 判检出；EPERM/SELinux/seccomp 拒绝不能算阳性。 */
    return tracer_pid != 0;
}

/* ============================================================
 * 综合检测（OR 判定）
 * ============================================================ */
static int detect_frida(void) {
    return detect_signal_handler() || detect_ptrace();
}

/* ============================================================
 * 答案计算
 * ============================================================ */
static const char* compute_answer(void) {
    static char result[33];
    if (detect_frida()) return "DETECTED_FRIDA_LOCKED_ANSWER";
    unsigned int seed = 20280722;
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
    int sig = detect_signal_handler();
    int ptr = detect_ptrace();

    snprintf(buf, sizeof(buf),
        "=== 雪落无痕 ===\n"
        "signal检测:   %s\n"
        "TracerPid检测: %s\n"
        "综合判定(OR): %s\n\n"
        "标记A: %s\n标记B: %s",
        sig ? "检出" : "安全",
        ptr ? "检出" : "安全",
        detect_frida() ? "检出" : "安全",
        REAL_MARK, FAKE_MARK);
    return buf;
}

/* ============================================================
 * JNI 导出
 * ============================================================ */

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Wk28_nativeSignal(JNIEnv *e, jclass c) {
    return detect_signal_handler();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Wk28_nativePtrace(JNIEnv *e, jclass c) {
    return detect_ptrace();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Wk28_nativeFridaDetect(JNIEnv *e, jclass c) {
    return detect_frida();
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Wk28_nativeAnswer(JNIEnv *e, jclass c) {
    return (*e)->NewStringUTF(e, compute_answer());
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Wk28_nativeStatus(JNIEnv *e, jclass c) {
    return (*e)->NewStringUTF(e, compute_status());
}
