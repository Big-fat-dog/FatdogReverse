/*
 * snow.cpp — 扶桑树 KL28 雪落无痕（C++ OOP 重构版，2026-10-04）
 *
 * 8 路信号 + 评分阈值制 + 加载期 (.init_array) 先跑。
 *
 *   ① 信号试点自检        —— 预装 SIGUSR1 handler 查询 + 自触发可复现性
 *   ② TracerPid 追踪      —— /proc/self/status 的真实 tracer
 *   ③ 可执行段私有脏页    —— smaps 里 file-backed r-x 段 Private_Dirty 异常
 *   ④ 无名可执行映射      —— 无 VMA 名的 r-x 段（注入落点「代码岛」）
 *   ⑤ ARM64 跳板扫描      —— 代码岛内 LDR X16/17,[PC] / BR X16/17 成簇
 *   ⑥ libc 关键函数入口    —— 内存 vs 磁盘 libc.so 的 prologue 差异
 *   ⑦ libc 代码段采样      —— 段内多点窗口 内存 vs 磁盘，抓非入口补丁
 *   ⑧ libc 符号解析完整性  —— dlsym+dladdr 归属校验（LD_PRELOAD / GOT 换库）
 *
 *   命中数 >= KL28_THRESHOLD(2) 才判定检出 —— 评分阈值制，防单点误杀。
 *
 * 【本关升级点 · 比 KL27 更深】
 *   KL27 已有 ⑦（段内采样），本关**再加一路 ⑧**：符号解析层面——⑦/⑥ 抓的是
 *   「改机器码」，⑧ 抓的是「换实现」（LD_PRELOAD、GOT 重定向、符号偷换）：
 *   机器码可以一个字节没改，但 dlsym("open") 解析结果已不在 libc.so 里。
 *   同时保留本关专属的 ①②（信号 + ptrace 进程级反调试），与注入痕迹层互补。
 *   监测点 4→5→6→7→**8** 递增。
 *
 * 【C++ 语言特性（本关重构的考点）】
 *   · 抽象基类 Probe + 纯虚 run()/sigil() + 虚析构：8 个真身派生类各自实现一路；
 *     调用点只持基类指针 → vtable 隐式派发（LDR X8,[X0]; LDR X9,[X8,#N]; BLR X9）。
 *   · RAII：SigTrial 构造时装 handler + 解屏蔽，析构自动恢复原 disposition 与
 *     sigmask —— 检查动作自身不留副作用（异常/提前 return 也不会漏恢复）。
 *   · 工厂 make_probe(kind) 用**函数内 static 对象**（C++11 magic static，首次调用
 *     才构造）：既保住虚派发，又避开「命名空间作用域静态对象构造晚于
 *     constructor(101)」这一初始化顺序坑（凡在 .init_array 里访问全局静态
 *     C++ 对象都是 UB，这里天然规避）。
 *   · 诱饵派生类（ThawProbe / MeltProbe）在工厂里被 new/取址一次，vtable 不被
 *     --gc-sections 删掉 —— 静态分析要恢复 vtable 才能分辨真身与诱饵。
 *
 * 【加载期检测】
 *   so 加载时 .init_array 先跑一遍并缓存相位（0=未执行 / 1=干净 / 2=命中）；
 *   nativeAnswer() 读缓存 —— 加载期一旦命中即永久锁定，事后 hook 运行期检测无效。
 *
 * SEED = 20280722
 * Flag: FLAG_18_KL28{snow_leaves_no_trace}
 * 标记（真）：Fatdog_snow  诱饵（假）：Fatdog_sow
 */

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>

#include "fuso_probe.h"

/* ============================================================
 * 诱饵标记：Fatdog_snow（真）/ Fatdog_sow（假·少 n）
 * ============================================================ */
static const char REAL_MARK[] = "Fatdog_snow";
static const char FAKE_MARK[] = "Fatdog_sow";

/* 评分阈值制：8 路信号里命中 >= 2 才判检出（验证时可 -DKL28_THRESHOLD=n 覆盖） */
#define KL28_SIG_COUNT 8
#ifndef KL28_THRESHOLD
#define KL28_THRESHOLD 2
#endif

/* 加载期相位 */
#define PHASE_UNRUN 0
#define PHASE_CLEAN 1
#define PHASE_HIT   2

/* ============================================================
 * RAII：SIGUSR1 自触发试点
 *   构造期「安装 handler + 解除本线程屏蔽」；析构期「恢复原 action 与 sigmask」。
 *   无论 run() 从哪条分支 return，恢复都会执行（RAII 的核心价值）。
 *
 * 平台守卫：SIGUSR1 / sigaction 是 Android(bionic) 语义；宿主(mingw) 的信号
 *   集合与 kill 行为不同（对不存在信号调用 kill 会直接终止进程），故这一路
 *   在非 __ANDROID__ 下不编译、运行期返回 0（守卫式，不记分）。
 * ============================================================ */
#if defined(__ANDROID__)
static volatile sig_atomic_t g_usr1_hits = 0;

static void sig_usr1_bump(int sig) {
    (void)sig;
    g_usr1_hits++;
}

class SigTrial {
public:
    SigTrial() : saved_act_(false), saved_mask_(false) {
        memset(&old_, 0, sizeof(old_));
        memset(&oldmask_, 0, sizeof(oldmask_));
    }
    ~SigTrial() { restore(); }

    /* 保存原 disposition → 解除本线程屏蔽 → 装试点 handler；任一步失败返回 false */
    bool arm() {
        if (sigaction(SIGUSR1, NULL, &old_) != 0) return false;
        saved_act_ = true;

        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGUSR1);
        if (sigprocmask(SIG_UNBLOCK, &mask, &oldmask_) == 0) saved_mask_ = true;

        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sig_usr1_bump;
        return sigaction(SIGUSR1, &sa, NULL) == 0;
    }

    /* 自触发并轮询等待 handler 执行；返回 true = 信号链路通 */
    bool fire() const {
        g_usr1_hits = 0;
        if (kill(getpid(), SIGUSR1) != 0) return false;
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 200000L;              /* 0.2ms */
        for (int i = 0; i < 50 && g_usr1_hits == 0; i++) {
            nanosleep(&ts, NULL);
        }
        return g_usr1_hits != 0;
    }

private:
    void restore() {
        if (saved_act_) sigaction(SIGUSR1, &old_, NULL);
        if (saved_mask_) sigprocmask(SIG_SETMASK, &oldmask_, NULL);
    }

    struct sigaction old_;
    sigset_t oldmask_;
    bool saved_act_;
    bool saved_mask_;
};
#endif /* __ANDROID__ */

/* ============================================================
 * 抽象基类：一路检测探针
 *   run()   —— 0=安全 / 1=命中（守卫式：读不到一律 0，不记分）
 *   sigil() —— 报告用的可读标识（App 端逐路展示）
 * ============================================================ */
class Probe {
public:
    Probe() {}
    virtual ~Probe() {}
    virtual int run() const = 0;
    virtual const char *sigil() const = 0;
};

/* ------------------------------------------------------------
 * ① 信号试点自检（FrostProbe）
 *   已被他人装自定义 handler → 命中；
 *   否则自装自触发，若仍收不到 → 信号链路被拦截，命中。
 * ------------------------------------------------------------ */
class FrostProbe : public Probe {
public:
    const char *sigil() const override { return "signal"; }

    int run() const override {
#if defined(__ANDROID__)
        struct sigaction cur;
        memset(&cur, 0, sizeof(cur));
        /* 守卫：查不到当前 disposition → 不记分 */
        if (sigaction(SIGUSR1, NULL, &cur) != 0) return 0;

        /* 已被他人安装自定义 handler（非默认/忽略）→ 疑似注入 */
        if (cur.sa_handler != SIG_DFL && cur.sa_handler != SIG_IGN) return 1;

        SigTrial trial;
        if (!trial.arm()) return 0;         /* 守卫：装不上 → 不记分 */

        /* 自身 handler 仍未能触发 → 信号被拦截/屏蔽，可疑 */
        return trial.fire() ? 0 : 1;
#else
        return 0;   /* 宿主无 Android 信号语义 → 守卫式不记分 */
#endif
    }
};

/* ------------------------------------------------------------
 * ② TracerPid 追踪检查（ChillProbe）
 *   仅真实存在的 tracer 判命中；EPERM/SELinux/seccomp 拒绝不算阳性。
 * ------------------------------------------------------------ */
class ChillProbe : public Probe {
public:
    const char *sigil() const override { return "tracer"; }

    int run() const override {
        FILE *f = fopen("/proc/self/status", "r");
        if (!f) return 0;

        char line[256];
        int tracer_pid = 0, seen = 0;
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                tracer_pid = atoi(line + 10);
                seen = 1;
                break;
            }
        }
        fclose(f);
        if (!seen) return 0;                /* 守卫：没读到该字段 → 不记分 */
        return tracer_pid != 0;
    }
};

/* ------------------------------------------------------------
 * ③④⑤⑥⑦⑧：注入痕迹层（实现见 fuso_probe.h）
 *   每路仅是一个薄派生类，把 fuso_* 信号接入统一的 Probe 接口。
 * ------------------------------------------------------------ */
class DriftProbe : public Probe {                    /* ③ 可执行段私有脏页 */
public:
    const char *sigil() const override { return "smaps_dirty"; }
    int run() const override { return fuso_smaps_dirty(); }
};

class FlurryProbe : public Probe {                   /* ④ 无名代码岛 */
public:
    const char *sigil() const override { return "anon_exec"; }
    int run() const override { return fuso_anon_exec(); }
};

class SquallProbe : public Probe {                   /* ⑤ ARM64 跳板 */
public:
    const char *sigil() const override { return "trampoline"; }
    int run() const override { return fuso_trampoline(); }
};

class RimeProbe : public Probe {                     /* ⑥ libc 入口比对 */
public:
    const char *sigil() const override { return "libc_entry"; }
    int run() const override { return fuso_libc_prologue(); }
};

class GlazeProbe : public Probe {                    /* ⑦ libc 段采样 */
public:
    const char *sigil() const override { return "libc_scan"; }
    int run() const override { return fuso_libc_scan(); }
};

class SleetProbe : public Probe {                    /* ⑧ libc 符号解析完整性（本关新增） */
public:
    const char *sigil() const override { return "libc_got"; }
    int run() const override { return fuso_libc_got(); }
};

/* ------------------------------------------------------------
 * 诱饵派生类（不参与计分；工厂里取址一次保 vtable）
 *   ThawProbe —— 假装扫 environ 找特征，正常永远找不到 → 恒 0
 *   MeltProbe —— 假装对一个不存在的模块做 CRC → 恒 0
 * ------------------------------------------------------------ */
class ThawProbe : public Probe {
public:
    const char *sigil() const override { return "environ"; }
    int run() const override {
        FILE *f = fopen("/proc/self/environ", "r");
        if (!f) return 0;
        char buf[512];
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = '\0';
        return (strstr(buf, "FRIDA_INJECT") != NULL) ? 1 : 0;   /* 真机会恒 0 */
    }
};

class MeltProbe : public Probe {
public:
    const char *sigil() const override { return "ghost"; }
    int run() const override {
        /* 幻影模块：正常根本不存在，dladdr 必然失败 → 恒 0 */
        Dl_info di;
        if (!dladdr((const void *)&melt_anchor, &di)) return 0;
        return (di.dli_fname && strstr(di.dli_fname, "libghost.so")) ? 1 : 0;
    }
private:
    static void melt_anchor(void) {}
};

/* ============================================================
 * 探针类型枚举 + 工厂
 *   真身 8 个参与计分；2 个诱饵仅被工厂引用（保 vtable）。
 * ============================================================ */
enum ProbeKind {
    kFrost = 0, kChill, kDrift, kFlurry, kSquall, kRime, kGlaze, kSleet,
    kThaw, kMelt                       /* 诱饵 */
};

/*
 * make_probe：用**函数内 static 对象**返回基类指针。
 *   · 首次调用才构造（magic static），规避静态构造顺序坑；
 *   · 返回 Probe* → 调用点做虚派发；
 *   · 诱饵分支同样被引用 → vtable 不会被 --gc-sections 删掉。
 */
static Probe *make_probe(int kind) {
    switch (kind) {
    case kChill:  { static ChillProbe  p; return &p; }
    case kDrift:  { static DriftProbe  p; return &p; }
    case kFlurry: { static FlurryProbe p; return &p; }
    case kSquall: { static SquallProbe p; return &p; }
    case kRime:   { static RimeProbe   p; return &p; }
    case kGlaze:  { static GlazeProbe  p; return &p; }
    case kSleet:  { static SleetProbe  p; return &p; }
    case kThaw:   { static ThawProbe   p; return &p; }   /* 诱饵 */
    case kMelt:   { static MeltProbe   p; return &p; }   /* 诱饵 */
    case kFrost:
    default:      { static FrostProbe  p; return &p; }
    }
}

/* 参与计分的 8 路（顺序与 UI 展示一致） */
static const int KL28_KINDS[KL28_SIG_COUNT] = {
    kFrost, kChill, kDrift, kFlurry, kSquall, kRime, kGlaze, kSleet
};

/* ============================================================
 * 评分：返回命中信号数（0..KL28_SIG_COUNT），多态遍历
 * ============================================================ */
static int detect_score(void) {
    int s = 0, i;
    for (i = 0; i < KL28_SIG_COUNT; i++) {
        s += make_probe(KL28_KINDS[i])->run();
    }
    return s;
}

static int probe_hit(int kind) {
    return make_probe(kind)->run();
}

/* ============================================================
 * 加载期检测缓存（.init_array 阶段写入）
 * ============================================================ */
static volatile int g_load_phase = PHASE_UNRUN;
static volatile int g_load_score = 0;

__attribute__((constructor(101)))
static void _snow_load_guard(void) {
    int s = detect_score();
    g_load_score = s;
    g_load_phase = (s >= KL28_THRESHOLD) ? PHASE_HIT : PHASE_CLEAN;
}

/* ============================================================
 * 综合检测（评分阈值制 + 加载期锁定）
 * ============================================================ */
static int detect_frida(void) {
    if (g_load_phase == PHASE_HIT) return 1;
    return detect_score() >= KL28_THRESHOLD;
}

/* ============================================================
 * 答案计算（LCG；seed 与老 C 版一致，语义零漂移）
 * ============================================================ */
static const char *compute_answer(void) {
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
static const char *load_phase_str(void) {
    switch (g_load_phase) {
        case PHASE_HIT:   return "已命中(2)";
        case PHASE_CLEAN: return "干净(1)";
        default:          return "未执行(0)";
    }
}

static const char *compute_status(void) {
    static char buf[1800];
    int sc = detect_score();

    snprintf(buf, sizeof(buf),
        "=== 雪落无痕（8 路评分阈值制 · 加载期先跑 · C++ OOP）===\n"
        "加载期相位(.init_array): %s   加载期命中数: %d\n"
        "------------------------------------------------------\n"
        "① 信号试点自检     : %-4s\n"
        "② TracerPid 追踪   : %-4s\n"
        "③ 可执行段私有脏页 : %-4s\n"
        "④ 无名可执行代码岛 : %-4s\n"
        "⑤ ARM64 跳板扫描   : %-4s\n"
        "⑥ libc 入口比对    : %-4s\n"
        "⑦ libc 段采样校验  : %-4s\n"
        "⑧ libc 符号完整性  : %-4s\n"
        "------------------------------------------------------\n"
        "命中 %d/%d 路，阈值 >= %d 判检出\n"
        "综合判定: %s\n\n"
        "标记A: %s\n标记B: %s",
        load_phase_str(), g_load_score,
        probe_hit(kFrost)  ? "命中" : "安全",
        probe_hit(kChill)  ? "命中" : "安全",
        probe_hit(kDrift)  ? "命中" : "安全",
        probe_hit(kFlurry) ? "命中" : "安全",
        probe_hit(kSquall) ? "命中" : "安全",
        probe_hit(kRime)   ? "命中" : "安全",
        probe_hit(kGlaze)  ? "命中" : "安全",
        probe_hit(kSleet)  ? "命中" : "安全",
        sc, KL28_SIG_COUNT, KL28_THRESHOLD,
        detect_frida() ? "检出" : "安全",
        REAL_MARK, FAKE_MARK);
    return buf;
}

/* ============================================================
 * JNI 导出（.cpp 里必须 extern "C"，规则 47）
 * ============================================================ */
extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Wk28_nativeSignal(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return probe_hit(kFrost);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Wk28_nativePtrace(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return probe_hit(kChill);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Wk28_nativeSmapsDirty(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return probe_hit(kDrift);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Wk28_nativeAnonExec(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return probe_hit(kFlurry);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Wk28_nativeTrampoline(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return probe_hit(kSquall);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Wk28_nativeLibcPrologue(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return probe_hit(kRime);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Wk28_nativeLibcScan(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return probe_hit(kGlaze);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Wk28_nativeLibcGot(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return probe_hit(kSleet);
}

/* 加载期相位：0=未执行 1=加载期干净 2=加载期已命中 */
extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Wk28_nativeLoadPhase(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return (jint)g_load_phase;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Wk28_nativeFridaDetect(JNIEnv *e, jclass c) {
    (void)e; (void)c;
    return detect_frida();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Wk28_nativeAnswer(JNIEnv *e, jclass c) {
    (void)c;
    return e->NewStringUTF(compute_answer());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Wk28_nativeStatus(JNIEnv *e, jclass c) {
    (void)c;
    return e->NewStringUTF(compute_status());
}
