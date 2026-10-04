/**
 * ice.c — 扶桑树 KL24 冰鉴悬镜
 *
 * 进程「运行时状态」层检测：4 路信号 + 评分阈值制 + 加载期 (.init_array) 先跑。
 *
 *   ① TracerPid 非零           —— /proc/self/status 有 tracer 挂上
 *   ② State ∈ {t,T}            —— 进程处于被 ptrace 停止态
 *   ③ 父进程链命中调试器名      —— PPid 的 cmdline 含 frida/gdb/lldb/gdbserver
 *   ④ status 结构完整性         —— /proc/self/status 被喂假/过滤（缺必需字段）
 *
 *   命中数 >= KL24_THRESHOLD(2) 才判定检出 —— 评分阈值制，
 *   避免部分 ROM 的 seccomp/SELinux 让单路信号误报时误杀正常玩家
 *   （沿用 KL15/KL19/KL28 教训，禁「任一命中即判」）。
 *
 * 【本关升级点 · 加载期检测】
 *   so 被 System.loadLibrary 加载时，.init_array 里的 constructor 先跑一遍检测
 *   并把结果缓存在 g_load_phase：
 *      0=未执行  1=加载期干净  2=加载期已命定
 *   nativeAnswer() 读的是这份缓存 —— 一旦加载期判检出，答案**永久锁定**，
 *   事后 hook 运行期检测函数也解不开；玩家必须抢在 so 加载之前动作
 *   （与 KL21-23「进关后点按钮才检测」形成时机递进）。
 *
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
 * 诱饵标记：Fatdog_siren（真）/ Fatdog_sren（假·少第二个 i）
 * 仅作报告展示，不参与答案。
 * ============================================================ */
static const char REAL_MARK[] = "Fatdog_siren";
static const char FAKE_MARK[] = "Fatdog_sren";

/* 评分阈值制：4 路信号里命中 >= 2 才判检出 */
#define KL24_SIG_COUNT 4
#define KL24_THRESHOLD 2

/* 加载期相位 */
#define PHASE_UNRUN 0
#define PHASE_CLEAN 1
#define PHASE_HIT   2

/* ============================================================
 * 信号①：TracerPid 检查
 * ============================================================ */
static int sig_tracer_pid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    int hit = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            const char *p = line + 10;
            while (*p && isspace((unsigned char)*p)) p++;
            if (atoi(p) != 0) hit = 1;
            break;
        }
    }

    fclose(f);
    return hit;
}

/* ============================================================
 * 信号②：进程状态字检查
 * ============================================================ */
static int sig_state(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    int hit = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "State:", 6) == 0) {
            const char *p = line + 6;
            while (*p && isspace((unsigned char)*p)) p++;
            /* t = 被 ptrace stop；T = 被停止 */
            if (*p == 't' || *p == 'T') hit = 1;
            break;
        }
    }

    fclose(f);
    return hit;
}

/* ============================================================
 * 信号③：父进程链检查
 *   读 /proc/self/status 的 PPid，再看 /proc/<ppid>/cmdline
 *   是否含调试器/注入器关键字（经典「debugger as parent」反调试）。
 * ============================================================ */
static int sig_ppid_chain(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    int ppid = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "PPid:", 5) == 0) {
            ppid = atoi(line + 5);
            break;
        }
    }
    fclose(f);
    if (ppid <= 0) return 0;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", ppid);

    FILE *g = fopen(path, "r");
    if (!g) return 0;

    char buf[256];
    size_t n = fread(buf, 1, sizeof(buf) - 1, g);
    fclose(g);
    if (n == 0) return 0;
    buf[n] = '\0';

    /* cmdline 以 '\0' 分隔参数，统一成空格便于 strstr */
    for (size_t i = 0; i < n; i++) {
        if (buf[i] == '\0') buf[i] = ' ';
    }

    if (strstr(buf, "frida") || strstr(buf, "gdb") ||
        strstr(buf, "lldb")  || strstr(buf, "gdbserver")) {
        return 1;
    }
    return 0;
}

/* ============================================================
 * 信号④：/proc/self/status 结构完整性
 *   正常 status 必然含 "TracerPid:" 与 "State:" 两个字段。
 *   若被 hook（喂了伪造的空壳/过滤过的内容）导致关键字段缺失 → 命中。
 *   这一路专治「hook fopen/fgets 把 status 喂假」的偷懒绕过。
 * ============================================================ */
static int sig_status_integrity(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;   /* 打不开不判异常，避免权限类误报 */

    int has_tracer = 0, has_state = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) has_tracer = 1;
        if (strncmp(line, "State:", 6) == 0) has_state = 1;
        if (has_tracer && has_state) break;
    }
    fclose(f);

    return (has_tracer && has_state) ? 0 : 1;
}

/* ============================================================
 * 评分：返回命中信号数（0..KL24_SIG_COUNT）
 * ============================================================ */
static int detect_score(void) {
    int s = 0;
    s += sig_tracer_pid();
    s += sig_state();
    s += sig_ppid_chain();
    s += sig_status_integrity();
    return s;
}

/* ============================================================
 * 加载期检测缓存（.init_array 阶段写入）
 * ============================================================ */
static volatile int g_load_phase = PHASE_UNRUN;
static volatile int g_load_score = 0;

/* constructor(101)：优先级 101 为可用最小值，确保在其它构造前先跑 */
__attribute__((constructor(101)))
static void _ice_load_guard(void) {
    int s = detect_score();
    g_load_score = s;
    g_load_phase = (s >= KL24_THRESHOLD) ? PHASE_HIT : PHASE_CLEAN;
}

/* ============================================================
 * 综合检测（评分阈值制 + 加载期锁定）
 * ============================================================ */
static int detect_frida(void) {
    /* 加载期已判定命中 → 永久锁定，运行期怎么 hook 都解不开 */
    if (g_load_phase == PHASE_HIT) return 1;
    /* 运行期再算一次（并入判定） */
    return detect_score() >= KL24_THRESHOLD;
}

/* ============================================================
 * 答案计算：基于 SEED 的确定性哈希
 *   检出 → 固定锁定串（提交必败）；未检出 → 真答案。
 * ============================================================ */
static const char* compute_answer(void) {
    static char result[33];
    if (detect_frida()) return "DETECTED_FRIDA_LOCKED_ANSWER";
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
static const char* load_phase_str(void) {
    switch (g_load_phase) {
        case PHASE_HIT:   return "已命中(2)";
        case PHASE_CLEAN: return "干净(1)";
        default:          return "未执行(0)";
    }
}

static const char* compute_status(void) {
    static char buf[1024];
    int tp  = sig_tracer_pid();
    int st  = sig_state();
    int pp  = sig_ppid_chain();
    int sf  = sig_status_integrity();
    int sc  = detect_score();

    snprintf(buf, sizeof(buf),
        "=== 冰鉴悬镜（评分阈值制 · 加载期先跑）===\n"
        "加载期相位(.init_array): %s   加载期命中数: %d\n"
        "--------------------------------------------------\n"
        "① TracerPid : %-4s\n"
        "② State     : %-4s\n"
        "③ 父进程链 : %-4s\n"
        "④ status完整: %-4s\n"
        "--------------------------------------------------\n"
        "命中 %d/%d 路，阈值 >= %d 判检出\n"
        "综合判定: %s\n\n"
        "标记A: %s\n标记B: %s",
        load_phase_str(), g_load_score,
        tp ? "命中" : "安全",
        st ? "命中" : "安全",
        pp ? "命中" : "安全",
        sf ? "命中" : "安全",
        sc, KL24_SIG_COUNT, KL24_THRESHOLD,
        detect_frida() ? "检出" : "安全",
        REAL_MARK, FAKE_MARK);
    return buf;
}

/* ============================================================
 * JNI 导出
 * ============================================================ */

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Qk_nativeTracerPid(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return sig_tracer_pid();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Qk_nativeState(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return sig_state();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Qk_nativePpidChain(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return sig_ppid_chain();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Qk_nativeStatusIntegrity(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return sig_status_integrity();
}

/* 加载期相位：0=未执行 1=加载期干净 2=加载期已命中 */
JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Qk_nativeLoadPhase(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return (jint)g_load_phase;
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Qk_nativeFridaDetect(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return detect_frida();
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Qk_nativeAnswer(JNIEnv *e, jclass c) {
    (void)c;
    return (*e)->NewStringUTF(e, compute_answer());
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Qk_nativeStatus(JNIEnv *e, jclass c) {
    (void)c;
    return (*e)->NewStringUTF(e, compute_status());
}
