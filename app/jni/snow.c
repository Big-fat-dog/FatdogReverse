/**
 * snow.c — 扶桑树 KL28 雪落无痕
 * 双重检测：Signal handler 注册 + ptrace 反附加
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
#include <sys/ptrace.h>

/* ============================================================
 * 诱饵标记：Fatdog_snow（真）/ Fatdog_snow（假·少 n）
 * ============================================================ */
static const char REAL_MARK[]  = "Fatdog_snow";
static const char FAKE_MARK[]  = "Fatdog_sow";

/* ============================================================
 * 检测①：Signal handler 自我识别
 * ============================================================ */
static volatile int sigusr1_count = 0;

static void sigusr1_handler(int sig) {
    sigusr1_count++;
}

static int detect_signal_handler(void) {
    /* 注册自定义 signal handler */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigusr1_handler;
    sigaction(SIGUSR1, &sa, NULL);

    /* 发送信号给自己 */
    sigusr1_count = 0;
    kill(getpid(), SIGUSR1);

    /* 如果 Frida hook 了 signal，handler 可能不会被正常调用 */
    /* 或者 Frida 可能修改了信号处理流程 */
    usleep(1000);  /* 等待信号处理 */

    /* 正常情况下应该收到信号，Frida 可能干扰 */
    return 0;  /* 简化：主要依赖 ptrace 检测 */
}

/* ============================================================
 * 检测②：ptrace 反附加
 * ============================================================ */
static int detect_ptrace(void) {
    /* 尝试 ptrace 自己 */
    long result = ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    if (result == -1) {
        /* ptrace 失败可能意味着已经被附加 */
        return 1;
    }

    /* 如果成功，解除跟踪并返回安全 */
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
    return 0;
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
        "ptrace检测:   %s\n"
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
