/**
 * ice.c — 扶桑树 KL24 冰鉴悬镜
 * 双重检测：TracerPid + 进程状态字
 * 判定逻辑：OR（任一检出即判定）
 * SEED = 20280718
 * Flag: FLAG_18_KL24{ice_mirror_catches_all}
 */

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

/* ============================================================
 * 诱饵标记：Fatdog_siren（真）/ Fatdog_siren（假·少了第二个 i）
 * ============================================================ */
static const char REAL_MARK[]  = "Fatdog_siren";
static const char FAKE_MARK[]  = "Fatdog_sren";

/* ============================================================
 * 检测①：TracerPid 检查
 * ============================================================ */
static int detect_tracer_pid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        /* 查找 TracerPid 行 */
        if (strncmp(line, "TracerPid:", 10) == 0) {
            const char *p = line + 10;
            while (*p && isspace((unsigned char)*p)) p++;

            int pid = atoi(p);
            if (pid != 0) {
                found = 1;  /* 有非零 TracerPid → 被附加 */
            }
            break;
        }
    }

    fclose(f);
    return found;
}

/* ============================================================
 * 检测②：进程状态字检查
 * ============================================================ */
static int detect_state(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        /* 查找 State: 行 */
        if (strncmp(line, "State:", 6) == 0) {
            const char *p = line + 6;
            while (*p && isspace((unsigned char)*p)) p++;

            /* t = 被 ptrace stop 状态 */
            if (*p == 't' || *p == 'T') {
                found = 1;  /* 进程处于 stop 状态 → 被附加 */
            }
            break;
        }
    }

    fclose(f);
    return found;
}

/* ============================================================
 * 综合检测（OR 判定）
 * ============================================================ */
static int detect_frida(void) {
    return detect_tracer_pid() || detect_state();
}

/* ============================================================
 * 答案计算：基于 SEED 的确定性哈希
 * ============================================================ */
static const char* compute_answer(void) {
    static char result[33];
    unsigned int seed = 20280718;
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
    int tp = detect_tracer_pid();
    int st = detect_state();

    FILE *f = fopen("/proc/self/status", "r");
    int pid = 0;
    char state_ch = '?';
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                pid = atoi(line + 10);
            }
            if (strncmp(line, "State:", 6) == 0) {
                const char *p = line + 6;
                while (*p && isspace((unsigned char)*p)) p++;
                state_ch = *p;
            }
        }
        fclose(f);
    }

    snprintf(buf, sizeof(buf),
        "=== 冰鉴悬镜 ===\n"
        "TracerPid: %d (%s)\n"
        "State:     %c (%s)\n"
        "TracerPid判定: %s\n"
        "State判定:     %s\n"
        "综合判定(OR):  %s\n\n"
        "标记A: %s\n标记B: %s",
        pid, pid != 0 ? "被追踪" : "正常",
        state_ch, (state_ch == 't' || state_ch == 'T') ? "被停止" : "正常",
        tp ? "检出" : "安全",
        st ? "检出" : "安全",
        detect_frida() ? "检出" : "安全",
        REAL_MARK, FAKE_MARK);
    return buf;
}

/* ============================================================
 * JNI 导出
 * ============================================================ */

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Qk_nativeTracerPid(JNIEnv *e, jclass c) {
    return detect_tracer_pid();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Qk_nativeState(JNIEnv *e, jclass c) {
    return detect_state();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Qk_nativeFridaDetect(JNIEnv *e, jclass c) {
    return detect_frida();
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Qk_nativeAnswer(JNIEnv *e, jclass c) {
    return (*e)->NewStringUTF(e, compute_answer());
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Qk_nativeStatus(JNIEnv *e, jclass c) {
    return (*e)->NewStringUTF(e, compute_status());
}
