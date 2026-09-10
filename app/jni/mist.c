/**
 * mist.c — 扶桑树 KL25 暮雾锁听
 * 三重检测：/proc/self/maps frida 特征 + 线程指纹（gum-js-loop/gmain 等）+ getauxval(AT_PHDR)
 * 判定逻辑：AND（三路条件全部成立才判定检出）
 * SEED = 20280719
 * Flag: FLAG_18_KL25{mist_locks_the_ears}
 */

#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/auxv.h>
#include <elf.h>
#include <dirent.h>

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
 * 检测②：线程指纹——扫描 /proc/self/task 下各线程的 comm 文件
 * Frida agent 注入后会拉起 gum-js-loop / gmain / gdbus / pool-frida 线程，
 * 顺序 open 两次 maps 的 fd2==fd1 在正常 Linux 上永不成立，这里改为真实可
 * 触发的线程名指纹（普通 App 无这些线程）。
 * ============================================================ */
static int detect_frida_threads(void) {
    DIR *d = opendir("/proc/self/task");
    if (!d) return 0;

    struct dirent *de;
    int found = 0;
    while ((de = readdir(d)) != NULL && !found) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", de->d_name);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        char name[64];
        int n = (int)read(fd, name, sizeof(name) - 1);
        close(fd);
        if (n <= 0) continue;
        name[n] = '\0';
        while (n > 0 && (name[n-1] == '\n' || name[n-1] == '\r')) name[--n] = '\0';
        if (strstr(name, "gum-js-loop") || strstr(name, "gmain") ||
            strstr(name, "gdbus") || strstr(name, "frida") ||
            strstr(name, "pool-frida")) {
            found = 1;
        }
    }
    closedir(d);
    return found;
}

/* ============================================================
 * 校验③：auxv 与磁盘 ELF 头一致性
 *
 * 不能把 arm64 的 AT_PHDR 塞进 32 位地址范围判断。这里按
 * AT_PHENT/AT_PHNUM 和 e_phoff 的页内偏移做 ABI 无关校验；
 * 返回 1 表示运行时元数据一致，作为 AND 判定的环境守卫。
 * ============================================================ */
static int detect_auxv_hook(void) {
    uintptr_t phdr = (uintptr_t)getauxval(AT_PHDR);
    uintptr_t phent = (uintptr_t)getauxval(AT_PHENT);
    uintptr_t phnum = (uintptr_t)getauxval(AT_PHNUM);
    if (phdr == 0 || phent == 0 || phnum == 0) return 0;

    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0) return 0;

    uint8_t h[64];
    ssize_t got = read(fd, h, 16);
    if (got != 16 || h[0] != 0x7f || h[1] != 'E' || h[2] != 'L' || h[3] != 'F') {
        close(fd);
        return 0;
    }

    int is64 = (h[4] == 2);
    lseek(fd, 0, SEEK_SET);
    got = read(fd, h, is64 ? 64 : 52);
    close(fd);
    if (got != (is64 ? 64 : 52)) return 0;

    uint64_t e_phoff;
    uint16_t e_phentsize, e_phnum;
    if (is64) {
        e_phoff = (uint64_t)h[32] | ((uint64_t)h[33] << 8) |
                  ((uint64_t)h[34] << 16) | ((uint64_t)h[35] << 24) |
                  ((uint64_t)h[36] << 32) | ((uint64_t)h[37] << 40) |
                  ((uint64_t)h[38] << 48) | ((uint64_t)h[39] << 56);
        e_phentsize = (uint16_t)(h[54] | (h[55] << 8));
        e_phnum = (uint16_t)(h[56] | (h[57] << 8));
    } else {
        e_phoff = (uint64_t)(h[28] | (h[29] << 8) | (h[30] << 16) | (h[31] << 24));
        e_phentsize = (uint16_t)(h[42] | (h[43] << 8));
        e_phnum = (uint16_t)(h[44] | (h[45] << 8));
    }

    if (phent != e_phentsize || phnum != e_phnum) return 0;
    if ((phdr & 0xFFFULL) != (e_phoff & 0xFFFULL)) return 0;
    return 1;
}

/* ============================================================
 * 综合检测（AND 判定：maps/线程命中且 auxv 一致）
 * ============================================================ */
static int detect_frida(void) {
    int maps = detect_maps_frida();
    int hook = detect_frida_threads();
    int auxv = detect_auxv_hook();

    /* AND：Frida 指纹与运行时结构一致性全部成立才判定 */
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
    int hook = detect_frida_threads();
    int auxv = detect_auxv_hook();

    snprintf(buf, sizeof(buf),
        "=== 暮雾锁听 ===\n"
        "maps特征:     %s\n"
        "线程指纹:     %s\n"
        "auxv一致:     %s\n"
        "综合判定(AND): %s\n\n"
        "标记A: %s\n标记B: %s",
        maps ? "检出" : "安全",
        hook ? "检出" : "安全",
        auxv ? "一致" : "异常",
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

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Rk_nativeThreadFinger(JNIEnv *e, jclass c) {
    return detect_frida_threads();
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
