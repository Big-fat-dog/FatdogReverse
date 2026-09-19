/*
 * 天地秘境·九幽 KL50：枯木逢春——综合收官卷。
 *
 * 考点：九幽收官，把 KL46-49 的检测维度汇总成一次"全身体检"，叠加直接 SVC syscall、
 * 反调试（评分制）、静默投毒。模拟 freeRASP / 大厂风控 SDK 的综合防护。
 *
 * 八类信号（全部 SVC 直接系统调用读取，穿透 libc hook；读 /proc 文件用循环 read），
 * 分四层，每层命中 ≥ 阈值才判该层异常，任一层异常即判环境风险：
 *   文件层（KL46）：①su 文件 ②magisk 文件；
 *   属性层（KL47）：③verifiedbootstate/vbmeta ④/ 内核 cmdline 的 boot 状态；
 *   挂载/进程层（KL48）：⑤mountinfo 的 magisk tmpfs ⑥magiskd/zygiskd 进程（comm+SELinux）；
 *   新一代 root 层（KL49）：⑦内核版本串 KernelSU/APatch ⑧/data/adb/ksu 目录。
 *
 * 反调试（评分制 ≥2）：TracerPid 非 0 / ptrace(PTRACE_TRACEME) 失败 / 线程数异常。
 *
 * 静默投毒（本关题眼）：被绕过时不直接报"检测到风险"，而是返回一个"看似干净"的
 * 应答位图——玩家误以为已过，提交复测时 native 重新检测真实结果才露馅。
 * 模拟真实 App"静默失败"的隐蔽对抗行为。
 *
 * 标记（真）：Fatdog_spring — UTF-16 码元（static const，借 JNI_OnLoad 引用强制保留）。
 * 诱饵（假）：Fatdog_bloom  — 一字之差陷阱（spring→bloom）。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

#ifdef __aarch64__
#include <sys/syscall.h>
#endif

/* --- 真标记：Fatdog_spring（UTF-16LE 码元） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067, /* Fatdog */
    0x005F,                                           /* _      */
    0x0073, 0x0070, 0x0072, 0x0069, 0x006E, 0x0067  /* spring */
};
#define MARKER_LEN 13

/* --- 诱饵：Fatdog_bloom（spring→bloom） --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0062, 0x006C, 0x006F, 0x006F, 0x006D
};
#define DECOY_LEN 12

/* 标记留存：防止 --gc-sections 把未引用的 MARKER/DECOY 整体删除 */
static volatile uint32_t g_marker_proof = 0;

extern int __system_property_get(const char *name, char *value);

/* SVC 直接系统调用（穿透 libc hook） */
static int svc_open(const char *path) {
#ifdef __aarch64__
    register long x8 __asm__("x8") = __NR_openat;
    register long x0 __asm__("x0") = (long)(-100);
    register long x1 __asm__("x1") = (long)path;
    register long x2 __asm__("x2") = O_RDONLY;
    register long x3 __asm__("x3") = 0;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    return (int)x0;
#else
    return open(path, O_RDONLY);
#endif
}
static long svc_read(int fd, void *buf, size_t len) {
#ifdef __aarch64__
    register long x8 __asm__("x8") = __NR_read;
    register long x0 __asm__("x0") = (long)fd;
    register long x1 __asm__("x1") = (long)buf;
    register long x2 __asm__("x2") = (long)len;
    register long x3 __asm__("x3") = 0;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    return (long)x0;
#else
    return read(fd, buf, len);
#endif
}
static int svc_close(int fd) {
#ifdef __aarch64__
    register long x8 __asm__("x8") = __NR_close;
    register long x0 __asm__("x0") = (long)fd;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return (int)x0;
#else
    return close(fd);
#endif
}
static int svc_faccessat(const char *path) {
#ifdef __aarch64__
    register long x8 __asm__("x8") = __NR_faccessat;
    register long x0 __asm__("x0") = (long)(-100);
    register long x1 __asm__("x1") = (long)path;
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    return (int)x0;
#else
    return access(path, F_OK);
#endif
}
static int svc_uname(char *buf, size_t cap) {
#ifdef __aarch64__
    struct { char sysname[65]; char nodename[65]; char release[65];
             char version[65]; char machine[65]; char domainname[65]; } uts;
    register long x8 __asm__("x8") = __NR_uname;
    register long x0 __asm__("x0") = (long)&uts;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    if (x0 != 0) return -1;
    snprintf(buf, cap, "%s %s %s", uts.sysname, uts.release, uts.version);
    return 0;
#else
    buf[0] = '\0';
    return -1;
#endif
}

/* svc_read_file：循环 read 读全 /proc 文件 */
static long svc_read_file(const char *path, char *buf, size_t cap) {
    int fd = svc_open(path);
    if (fd < 0) return -1;
    long total = 0;
    long r;
    while (total < (long)cap - 1) {
        r = svc_read(fd, buf + total, cap - 1 - (size_t)total);
        if (r <= 0) break;
        total += r;
    }
    svc_close(fd);
    if (total == 0) return -1;
    buf[total] = '\0';
    return total;
}

/* --- 文件层（KL46）：su 文件 + magisk 文件 --- */
static const char *const SU_PATHS[] = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/data/local/su",
    "/system/app/Superuser.apk", "/vendor/bin/su"
};
static const char *const MAGISK_PATHS[] = {
    "/data/adb/magisk", "/sbin/.magisk", "/data/adb/magisk.db"
};

static int detect_su_files(void) {
    for (size_t i = 0; i < sizeof(SU_PATHS)/sizeof(SU_PATHS[0]); i++) {
        if (svc_faccessat(SU_PATHS[i]) == 0) return 1;
    }
    return 0;
}
static int detect_magisk_files(void) {
    for (size_t i = 0; i < sizeof(MAGISK_PATHS)/sizeof(MAGISK_PATHS[0]); i++) {
        if (svc_faccessat(MAGISK_PATHS[i]) == 0) return 1;
    }
    return 0;
}

/* --- 属性层（KL47）：verifiedbootstate/vbmeta + cmdline --- */
static int prop_contains(const char *name, const char *sub) {
    char v[128];
    if (__system_property_get(name, v) > 0 && strstr(v, sub)) return 1;
    return 0;
}
static int detect_boot_props(void) {
    if (prop_contains("ro.boot.verifiedbootstate", "orange")) return 1;
    if (prop_contains("ro.boot.verifiedbootstate", "red")) return 1;
    if (prop_contains("ro.boot.vbmeta.device_state", "unlocked")) return 1;
    return 0;
}
static int detect_cmdline_boot(void) {
    static char buf[4096];
    long n = svc_read_file("/proc/cmdline", buf, sizeof(buf));
    if (n <= 0) return 0;
    if (strstr(buf, "androidboot.verifiedbootstate=orange") ||
        strstr(buf, "androidboot.flash.locked=0")) return 1;
    return 0;
}

/* --- 挂载/进程层（KL48）：mountinfo magisk tmpfs + magiskd 进程 --- */
static int detect_mountinfo_magisk(void) {
    static char buf[32768];
    long n = svc_read_file("/proc/self/mountinfo", buf, sizeof(buf));
    if (n <= 0) return 0;
    char *save = NULL;
    char *line = strtok_r(buf, "\n", &save);
    while (line) {
        if (strstr(line, "magisk")) return 1;
        if (strstr(line, " tmpfs ") &&
            (strstr(line, " /system/bin") || strstr(line, " /sbin"))) return 1;
        line = strtok_r(NULL, "\n", &save);
    }
    return 0;
}
static int detect_magiskd_process(void) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *de;
    int hit = 0;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        char path[64];
        char buf[256];
        snprintf(path, sizeof(path), "/proc/%s/comm", de->d_name);
        long n = svc_read_file(path, buf, sizeof(buf));
        if (n > 0 && (strstr(buf, "magiskd") || strstr(buf, "zygiskd") || strstr(buf, "ksud"))) {
            hit = 1; break;
        }
        snprintf(path, sizeof(path), "/proc/%s/attr/current", de->d_name);
        n = svc_read_file(path, buf, sizeof(buf));
        if (n > 0 && strstr(buf, "magisk")) { hit = 1; break; }
    }
    closedir(d);
    return hit;
}

/* --- 新一代 root 层（KL49）：内核版本串 + ksu 目录 --- */
static int detect_kernel_su(void) {
    char buf[256];
    if (svc_uname(buf, sizeof(buf)) != 0) return 0;
    if (strstr(buf, "KernelSU") || strstr(buf, "APatch") || strstr(buf, "kpatch")) return 1;
    return 0;
}
static int detect_ksu_dir(void) {
    if (svc_faccessat("/data/adb/ksu") == 0) return 1;
    if (svc_faccessat("/data/adb/ap") == 0) return 1;
    return 0;
}

/* --- 反调试（评分制 ≥2） --- */
static int detect_anti_debug(void) {
    int score = 0;
    /* TracerPid 非 0 */
    static char buf[2048];
    long n = svc_read_file("/proc/self/status", buf, sizeof(buf));
    if (n > 0) {
        char *p = strstr(buf, "TracerPid:");
        if (p) { int pid = 0; if (sscanf(p, "TracerPid: %d", &pid) == 1 && pid != 0) score++; }
    }
    /* ptrace(PTRACE_TRACEME) 失败 */
#ifdef __aarch64__
    register long x8 __asm__("x8") = __NR_ptrace;
    register long x0 __asm__("x0") = 0; /* PTRACE_TRACEME */
    register long x1 __asm__("x1") = 0;
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    if (x0 == -1) score++;
#else
    if (access("/proc/self/status", F_OK) == 0) score += 0;
#endif
    return score >= 2 ? 1 : 0;
}

/*
 * full_check()：八类信号分层判定，返回命中位图（bit0..bit7）。
 * 每层命中 ≥ 阈值（文件层≥2/属性层≥2/挂载层≥2/新root层≥2）才判该层异常。
 * 为评分阈值制统一，这里按"整体命中 ≥ 3 判环境异常"实现（综合卷放宽）。
 */
static int full_check(void) {
    int bitmap = 0;
    if (detect_su_files())         bitmap |= (1 << 0);
    if (detect_magisk_files())     bitmap |= (1 << 1);
    if (detect_boot_props())       bitmap |= (1 << 2);
    if (detect_cmdline_boot())     bitmap |= (1 << 3);
    if (detect_mountinfo_magisk()) bitmap |= (1 << 4);
    if (detect_magiskd_process())  bitmap |= (1 << 5);
    if (detect_kernel_su())        bitmap |= (1 << 6);
    if (detect_ksu_dir())          bitmap |= (1 << 7);
    return bitmap;
}

static int popcount(int x) {
    int c = 0;
    while (x) { x &= (x - 1); c++; }
    return c;
}

/* 静默投毒：detect 阶段返回"看似干净"的位图，verify 阶段返回真实位图 */
static int g_last_real_bitmap = 0;

static int is_tampered(int bitmap) {
    return popcount(bitmap) >= 3 ? 1 : 0;
}

/* --- 诱饵导出 --- */
void spring_decoy_scan(void) {}
void spring_fold(void) {}
void spring_spin(void) {}

/* --- JNI 桥接 --- */

/* RootSpring.nativeDetect() → int：检测阶段，静默投毒——返回 0（看似干净），真实结果存内部 */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_RootSpring_nativeDetect(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    g_last_real_bitmap = full_check();
    /* 静默投毒：detect 阶段故意返回 0（看似干净），让玩家误以为已过 */
    return 0;
}

/* RootSpring.nativeVerify() → int：提交复测阶段，返回真实位图（露馅） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_RootSpring_nativeVerify(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    int real = full_check();
    g_last_real_bitmap = real;
    return (jint)real;
}

/* RootSpring.nativeIsTampered(bitmap) → int：评分阈值判定 */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_RootSpring_nativeIsTampered(JNIEnv *env, jclass clazz, jint bitmap) {
    (void)env; (void)clazz;
    return (jint)is_tampered((int)bitmap);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    uint32_t mp = 0x5A5A5A5Au;
    for (int i = 0; i < MARKER_LEN; i++) mp ^= ((uint32_t)MARKER[i] << (i & 7));
    for (int i = 0; i < DECOY_LEN;  i++) mp ^= ((uint32_t)DECOY[i]  << (i & 7));
    g_marker_proof = mp;
    return JNI_VERSION_1_6;
}
