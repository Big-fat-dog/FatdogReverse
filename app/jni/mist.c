/**
 * mist.c — 扶桑树 KL25 暮雾锁听
 * 三重检测：/proc/self/maps frida 特征 + open(/proc/self/maps) 父进程检查 + getauxval(AT_PHDR)
 * 判定逻辑：NAND（全部触发才判定）
 * SEED = 20280719
 * Flag: FLAG_18_KL25{mist_locks_the_ears}
 */

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/auxv.h>
#include <elf.h>

/* ============================================================
 * 诱饵标记：Fatdog_gloom（真）/ Fatdog_gloom（假·少 o）
 * ============================================================ */
static const char REAL_MARK[]  = "Fatdog_gloom";
static const char FAKE_MARK[]  = "Fatdog_glom";

/* ============================================================
 * frida 特征字节
 * ============================================================ */
static const char FRIDA_SIG[] = "frida";
#define SIG_LEN 5

/* ============================================================
 * 检测①：maps 搜索 frida 特征
 * ============================================================ */
static int detect_maps_frida(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        int len = strlen(line);
        for (int i = 0; i < len - SIG_LEN; i++) {
            if (memcmp(line + i, FRIDA_SIG, SIG_LEN) == 0) {
                found = 1;
                break;
            }
        }
        if (found) break;
    }

    fclose(f);
    return found;
}

/* ============================================================
 * 检测②：/proc/self/maps 打开检查（检测 open hook）
 * ============================================================ */
static int detect_open_hook(void) {
    /* 尝试打开 maps 两次，比较描述符号 */
    int fd1 = open("/proc/self/maps", O_RDONLY);
    int fd2 = open("/proc/self/maps", O_RDONLY);

    int suspicious = 0;
    if (fd1 >= 0 && fd2 >= 0) {
        /* 正常情况下 fd 应该不同且递增 */
        if (fd2 == fd1) {
            suspicious = 1;  /* fd 被 hook 了，返回相同值 */
        }
        /* 检查 fd 是否异常大（可能被 hook 层拦截） */
        if (fd1 > 100 || fd2 > 100) {
            suspicious = 1;
        }
        close(fd1);
        close(fd2);
    }

    return suspicious;
}

/* ============================================================
 * 检测③：auxv AT_PHDR 检查
 * ============================================================ */
static int detect_auxv_hook(void) {
    unsigned long phdr = (unsigned long)getauxval(AT_PHDR);

    /* 正常 phdr 应该在合理的 ELF 加载范围内 */
    if (phdr == 0) return 1;  /* 异常：AT_PHDR 为零 */
    if (phdr > 0x80000000UL && phdr < 0xC0000000UL) {
        /* 这个范围通常是正常的 */
        return 0;
    }

    /* 检查是否在常见的 frida 注入范围内 */
    if (phdr >= 0x70000000UL && phdr <= 0x7FFFFFFFUL) {
        return 1;  /* 可疑：frida 注入区域 */
    }

    return 0;
}

/* ============================================================
 * 综合检测（NAND 判定：全部触发才判定）
 * ============================================================ */
static int detect_frida(void) {
    int maps = detect_maps_frida();
    int hook = detect_open_hook();
    int auxv = detect_auxv_hook();

    /* NAND：只有三路都触发才判定 Frida 存在 */
    return maps && hook && auxv;
}

/* ============================================================
 * 答案计算
 * ============================================================ */
static const char* compute_answer(void) {
    static char result[33];
    unsigned int seed = 20280719;
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
    int maps = detect_maps_frida();
    int hook = detect_open_hook();
    int auxv = detect_auxv_hook();

    snprintf(buf, sizeof(buf),
        "=== 暮雾锁听 ===\n"
        "maps特征:     %s\n"
        "open hook:    %s\n"
        "auxv hook:    %s\n"
        "综合判定(NAND): %s\n\n"
        "标记A: %s\n标记B: %s",
        maps ? "检出" : "安全",
        hook ? "检出" : "安全",
        auxv ? "检出" : "安全",
        detect_frida() ? "检出" : "安全",
        REAL_MARK, FAKE_MARK);
    return buf;
}

/* ============================================================
 * JNI 导出
 * ============================================================ */

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Rk_nativeMapsFrida(JNIEnv *e, jclass c) {
    return detect_maps_frida();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Rk_nativeOpenHook(JNIEnv *e, jclass c) {
    return detect_open_hook();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Rk_nativeAuxvHook(JNIEnv *e, jclass c) {
    return detect_auxv_hook();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Rk_nativeFridaDetect(JNIEnv *e, jclass c) {
    return detect_frida();
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Rk_nativeAnswer(JNIEnv *e, jclass c) {
    return (*e)->NewStringUTF(e, compute_answer());
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Rk_nativeStatus(JNIEnv *e, jclass c) {
    return (*e)->NewStringUTF(e, compute_status());
}
