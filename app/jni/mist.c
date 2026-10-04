/**
 * mist.c — 扶桑树 KL25 暮雾锁听
 *
 * 内存 / 线程 / 结构一致性层检测：5 路信号 + 评分阈值制 + 加载期 (.init_array) 先跑。
 *
 *   ① maps 搜 frida 特征          —— /proc/self/maps 命中 frida/gadget/gum-js-loop
 *   ② 线程名指纹                   —— /proc/self/task/<tid>/comm 命中 frida 专属线程名
 *   ③ auxv/ELF 一致性 (守卫)       —— AT_PHDR/PHENT/PHNUM 与磁盘头对齐；读到但不一致记 1 分
 *   ④ 线程数一致性 (防枚举被 hook) —— status 的 Threads 与 /proc/self/task 目录数越界不符
 *   ⑤ maps 幻影可执行映射          —— r-x 段里出现 memfd: / (deleted)，疑似注入落地
 *
 *   命中数 >= KL25_THRESHOLD(2) 才判检出 —— 评分阈值制。
 *   注意 auxv 为「守卫」：一致记 0 分、不一致记 1 分；因此无 Frida 时基线恒为 0，
 *   单路信号（如某 ROM 让 auxv 读失败）不会误判。
 *
 * 【本关升级点 · 加载期检测】
 *   so 加载时 .init_array 先跑一遍并缓存相位（0=未执行 / 1=干净 / 2=命中）；
 *   nativeAnswer() 读缓存 —— 加载期一旦命中即永久锁定，事后 hook 运行期检测无效。
 *
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
 * 诱饵标记：Fatdog_gloom（真）/ Fatdog_glom（假·少 o）
 * ============================================================ */
static const char REAL_MARK[] = "Fatdog_gloom";
static const char FAKE_MARK[] = "Fatdog_glom";

/* 评分阈值制：5 路信号里命中 >= 2 才判检出 */
#define KL25_SIG_COUNT 5
#define KL25_THRESHOLD 2

/* 加载期相位 */
#define PHASE_UNRUN 0
#define PHASE_CLEAN 1
#define PHASE_HIT   2

/* ============================================================
 * 信号①：maps 搜索 frida 特征
 * ============================================================ */
static const char FRIDA_SIG[] = "frida";
#define SIG_LEN 5

static int detect_maps_frida(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        int len = (int)strlen(line);
        for (int i = 0; i < len - SIG_LEN; i++) {
            if (memcmp(line + i, FRIDA_SIG, SIG_LEN) == 0) { found = 1; break; }
        }
        if (found) break;
    }

    fclose(f);
    return found;
}

/* ============================================================
 * 信号②：线程指纹——扫描 /proc/self/task 下各线程的 comm 文件
 *   Frida agent 注入后会拉起 gum-js-loop / pool-frida / linjector 线程。
 *   普通 App 无这些线程名（已剔除 gmain/gdbus 等 GLib 误报源）。
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
        if (strstr(name, "gum-js-loop") || strstr(name, "pool-frida") ||
            strstr(name, "frida") || strstr(name, "linjector")) {
            found = 1;
        }
    }
    closedir(d);
    return found;
}

/* ============================================================
 * 信号③（守卫）：auxv 与磁盘 ELF 头一致性（三态）
 *   AUXV_OK   = 1  一致（正常）
 *   AUXV_BAD  = 0  读到但不一致 —— 只有这一态才记异常分
 *   AUXV_UNREAD = -1 读不到（getauxval 为 0 / 打不开 exe）—— 不记分，
 *                   避免部分 ROM/容器环境下读失败被误判成"被 hook"
 *   nativeAuxvHook() 对外仍返回 1=一致 / 0=其余，供 App 展示。
 * ============================================================ */
#define AUXV_OK      1
#define AUXV_BAD     0
#define AUXV_UNREAD (-1)

static int auxv_state(void) {
    uintptr_t phdr  = (uintptr_t)getauxval(AT_PHDR);
    uintptr_t phent = (uintptr_t)getauxval(AT_PHENT);
    uintptr_t phnum = (uintptr_t)getauxval(AT_PHNUM);
    if (phdr == 0 || phent == 0 || phnum == 0) return AUXV_UNREAD;

    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0) return AUXV_UNREAD;

    uint8_t h[64];
    ssize_t got = read(fd, h, 16);
    if (got != 16 || h[0] != 0x7f || h[1] != 'E' || h[2] != 'L' || h[3] != 'F') {
        close(fd);
        return AUXV_UNREAD;
    }

    int is64 = (h[4] == 2);
    lseek(fd, 0, SEEK_SET);
    got = read(fd, h, is64 ? 64 : 52);
    close(fd);
    if (got != (is64 ? 64 : 52)) return AUXV_UNREAD;

    uint64_t e_phoff;
    uint16_t e_phentsize, e_phnum;
    if (is64) {
        e_phoff = (uint64_t)h[32] | ((uint64_t)h[33] << 8) |
                  ((uint64_t)h[34] << 16) | ((uint64_t)h[35] << 24) |
                  ((uint64_t)h[36] << 32) | ((uint64_t)h[37] << 40) |
                  ((uint64_t)h[38] << 48) | ((uint64_t)h[39] << 56);
        e_phentsize = (uint16_t)(h[54] | (h[55] << 8));
        e_phnum     = (uint16_t)(h[56] | (h[57] << 8));
    } else {
        e_phoff = (uint64_t)(h[28] | (h[29] << 8) | (h[30] << 16) | (h[31] << 24));
        e_phentsize = (uint16_t)(h[42] | (h[43] << 8));
        e_phnum     = (uint16_t)(h[44] | (h[45] << 8));
    }

    if (phent != e_phentsize || phnum != e_phnum) return AUXV_BAD;
    if ((phdr & 0xFFFULL) != (e_phoff & 0xFFFULL)) return AUXV_BAD;
    return AUXV_OK;
}

/* 对外展示：1=一致 0=异常/读不到 */
static int detect_auxv_hook(void) {
    return (auxv_state() == AUXV_OK) ? 1 : 0;
}

/* ============================================================
 * 信号④：线程数一致性（防「枚举被 hook」）
 *   对比 status 的 Threads 字段与 /proc/self/task 实际数字目录数。
 *   若玩家 hook opendir/readdir 藏掉 Frida 线程，两者会明显对不上。
 *   容差 >= 2，避免线程创建/销毁竞态导致误报。
 * ============================================================ */
static int detect_thread_count_mismatch(void) {
    int from_status = -1;

    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Threads:", 8) == 0) {
                from_status = atoi(line + 8);
                break;
            }
        }
        fclose(f);
    }
    if (from_status <= 0) return 0;

    DIR *d = opendir("/proc/self/task");
    if (!d) return 0;
    int counted = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] >= '0' && de->d_name[0] <= '9') counted++;
    }
    closedir(d);
    if (counted <= 0) return 0;

    int diff = from_status - counted;
    if (diff < 0) diff = -diff;
    return (diff >= 2) ? 1 : 0;
}

/* ============================================================
 * 信号⑤：maps 幻影可执行映射
 *   在 r-x/rwx 段里出现 memfd: 或 (deleted) —— Frida/注入器把代码落到
 *   匿名共享内存或已删除临时文件上的典型形态。
 * ============================================================ */
static int detect_maps_phantom(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        /* 段权限在第 2 列（index 1）；这里直接判断是否含 'x' 且命中幻影特征 */
        int exec = 0;
        char *sp = strchr(line, ' ');
        if (sp) {
            /* line 形如: addr perms offset dev inode path */
            char perms[8] = {0};
            if (sscanf(sp + 1, "%7s", perms) == 1 && strchr(perms, 'x')) exec = 1;
        }
        if (exec && (strstr(line, "memfd:") || strstr(line, "(deleted)"))) {
            found = 1;
            break;
        }
    }

    fclose(f);
    return found;
}

/* ============================================================
 * 评分：返回命中信号数（0..KL25_SIG_COUNT）
 *   auxv 为守卫：一致记 0 分、不一致记 1 分。
 * ============================================================ */
static int detect_score(void) {
    int s = 0;
    s += detect_maps_frida();
    s += detect_frida_threads();
    s += (auxv_state() == AUXV_BAD) ? 1 : 0;   /* 守卫：仅"读到但不一致"才记分 */
    s += detect_thread_count_mismatch();
    s += detect_maps_phantom();
    return s;
}

/* ============================================================
 * 加载期检测缓存（.init_array 阶段写入）
 * ============================================================ */
static volatile int g_load_phase = PHASE_UNRUN;
static volatile int g_load_score = 0;

__attribute__((constructor(101)))
static void _mist_load_guard(void) {
    int s = detect_score();
    g_load_score = s;
    g_load_phase = (s >= KL25_THRESHOLD) ? PHASE_HIT : PHASE_CLEAN;
}

/* ============================================================
 * 综合检测（评分阈值制 + 加载期锁定）
 * ============================================================ */
static int detect_frida(void) {
    if (g_load_phase == PHASE_HIT) return 1;
    return detect_score() >= KL25_THRESHOLD;
}

/* ============================================================
 * 答案计算
 * ============================================================ */
static const char* compute_answer(void) {
    static char result[33];
    if (detect_frida()) return "DETECTED_FRIDA_LOCKED_ANSWER";
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
static const char* load_phase_str(void) {
    switch (g_load_phase) {
        case PHASE_HIT:   return "已命中(2)";
        case PHASE_CLEAN: return "干净(1)";
        default:          return "未执行(0)";
    }
}

static const char* compute_status(void) {
    static char buf[1200];
    int maps = detect_maps_frida();
    int thr  = detect_frida_threads();
    int auxs = auxv_state();
    int tcnt = detect_thread_count_mismatch();
    int phan = detect_maps_phantom();
    int sc   = detect_score();
    const char *aux_txt = (auxs == AUXV_OK) ? "一致" : (auxs == AUXV_BAD ? "不一致" : "读不到");

    snprintf(buf, sizeof(buf),
        "=== 暮雾锁听（评分阈值制 · 加载期先跑）===\n"
        "加载期相位(.init_array): %s   加载期命中数: %d\n"
        "--------------------------------------------------\n"
        "① maps frida 特征  : %-4s\n"
        "② 线程名指纹       : %-4s\n"
        "③ auxv/ELF 一致性  : %-4s (守卫，读到但不一致才记分)\n"
        "④ 线程数一致性     : %-4s\n"
        "⑤ maps 幻影映射    : %-4s\n"
        "--------------------------------------------------\n"
        "命中 %d/%d 路，阈值 >= %d 判检出\n"
        "综合判定: %s\n\n"
        "标记A: %s\n标记B: %s",
        load_phase_str(), g_load_score,
        maps ? "命中" : "安全",
        thr  ? "命中" : "安全",
        aux_txt,
        tcnt ? "异常" : "正常",
        phan ? "命中" : "安全",
        sc, KL25_SIG_COUNT, KL25_THRESHOLD,
        detect_frida() ? "检出" : "安全",
        REAL_MARK, FAKE_MARK);
    return buf;
}

/* ============================================================
 * JNI 导出
 * ============================================================ */

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Rk_nativeMapsFrida(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return detect_maps_frida();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Rk_nativeThreadFinger(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return detect_frida_threads();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Rk_nativeAuxvHook(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return detect_auxv_hook();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Rk_nativeThreadCountCheck(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return detect_thread_count_mismatch();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Rk_nativeMapsPhantom(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return detect_maps_phantom();
}

/* 加载期相位：0=未执行 1=加载期干净 2=加载期已命中 */
JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Rk_nativeLoadPhase(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return (jint)g_load_phase;
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Rk_nativeFridaDetect(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return detect_frida();
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Rk_nativeAnswer(JNIEnv *e, jclass c) {
    (void)c;
    return (*e)->NewStringUTF(e, compute_answer());
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Rk_nativeStatus(JNIEnv *e, jclass c) {
    (void)c;
    return (*e)->NewStringUTF(e, compute_status());
}
