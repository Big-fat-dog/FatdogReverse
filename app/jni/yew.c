/*
 * 天地秘境·九幽 KL48：斩草除根——挂载点 / mount namespace 深检 + magiskd 进程检测。
 *
 * 考点：Magisk 是 systemless（不落盘改 /system，而是运行时用 tmpfs 覆盖挂载）。
 * 但 Shamiko/Zygisk 的隐藏手段是「hook libc 的 fopen/open/read/access」——把 App
 * 进程里读到的挂载表、进程列表过滤成干净版。所以检测方必须**用 SVC 直接系统调用
 * 绕过 libc hook**，直读内核导出的真相。
 *
 * 七类信号（全部用 SVC 直连内核读取，穿透 Shamiko 的 libc hook）：
 *   ① /proc/self/mountinfo：搜索 magisk tmpfs 覆盖挂载（SVC 直读，Shamiko 的 fopen hook 拦不住）；
 *   ② /sbin/.magisk、/data/adb/magisk 挂载点（SVC faccessat 直探）；
 *   ③ dex2oat loop mounts（LSPosed 注入特征：/apex 上的 loop 挂载）；
 *   ④ magiskd/zygiskd 进程：读 /proc/<pid>/comm（线程名，非 cmdline）+ SELinux context
 *      /proc/<pid>/attr/current 里的 u:r:magisk:s0（SELinux domain 是内核级，Shamiko 无法伪造）；
 *   ⑤ /proc/self/mounts 里的 magisk 字样；
 *   ⑥ 环境变量 MAGISK_VER_CODE / KSU_VER_CODE（读 /proc/self/environ）；
 *   ⑦ ro.dalvik.vm.native.bridge 非空 或 /data/adb/modules 目录存在。
 *
 * 破解路线：
 *   ① Magisk DenyList/Shamiko 解除 tmpfs 覆盖挂载（umount 目标命名空间）；
 *   ② Zygisk-Assistant / ZygiskNext 的 unmount 功能隐藏 bind mounts；
 *   ③ hook 检测函数出口返回 0（SVC 直读无法用 libc hook 拦截，只能 hook so 自身）；
 *   ④ patch so 改判定。
 *
 * 标记（真）：Fatdog_hook  — UTF-16 码元（static const，借 JNI_OnLoad 引用强制保留）。
 * 诱饵（假）：Fatdog_anti   — 一字之差陷阱（hook→anti）。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

#ifdef __aarch64__
#include <sys/syscall.h>
#endif

/* --- 真标记：Fatdog_hook（UTF-16LE 码元） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067, /* Fatdog */
    0x005F,                                           /* _      */
    0x0068, 0x006F, 0x006F, 0x006B                  /* hook   */
};
#define MARKER_LEN 11

/* --- 诱饵：Fatdog_anti（hook→anti） --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0061, 0x006E, 0x0074, 0x0069
};
#define DECOY_LEN 11

/* 标记留存：防止 --gc-sections 把未引用的 MARKER/DECOY 整体删除 */
static volatile uint32_t g_marker_proof = 0;

/* 判定阈值：七类信号命中 ≥ 2 才判环境异常（评分制，防单点误杀）。 */
#define TAMPER_THRESHOLD 2

extern int __system_property_get(const char *name, char *value);

/*
 * SVC 直接系统调用：绕过 Shamiko 对 libc fopen/open/read/access 的 hook。
 * 返回：svc_open 成功返回 fd，失败 -1；svc_read 返回读取字节数。
 * 其它 ABI（非 arm64）回退 libc 调用（host 语法体检用）。
 */
static int svc_open(const char *path, int flags) {
#ifdef __aarch64__
    register long x8 __asm__("x8") = __NR_openat;
    register long x0 __asm__("x0") = (long)(-100); /* AT_FDCWD */
    register long x1 __asm__("x1") = (long)path;
    register long x2 __asm__("x2") = (long)flags;
    register long x3 __asm__("x3") = 0;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    return (int)x0;
#else
    return open(path, flags);
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

/*
 * svc_read_file：用 SVC 直读整个文件到 buf（穿透 libc hook）。
 * 关键：/proc 文件是流式的，单次 read 只返回部分内容（约 4KB），
 * 必须循环 read 直到读完（返回 0）或读满，否则会漏掉后半部分（KL48 踩过：
 * 单次 read 只读到 mountinfo 前 35 行，漏掉后面 12 条 magisk 挂载）。
 * 返回读取字节数，失败返回 -1。
 */
static long svc_read_file(const char *path, char *buf, size_t cap) {
    int fd = svc_open(path, O_RDONLY);
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

/* --- 信号①：/proc/self/mountinfo 里的 magisk/tmpfs 覆盖挂载（SVC 直读） --- */
static int detect_mountinfo_magisk(void) {
    static char buf[32768];
    long n = svc_read_file("/proc/self/mountinfo", buf, sizeof(buf));
    if (n <= 0) return 0;
    /* 逐行扫描（mountinfo 行以 \n 分隔） */
    char *line = buf;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (strstr(line, "magisk")) return 1;
        if (strstr(line, " tmpfs ") &&
            (strstr(line, " /system/bin") || strstr(line, " /system/xbin") || strstr(line, " /sbin"))) {
            return 1;
        }
        if (!nl) break;
        line = nl + 1;
    }
    return 0;
}

/* --- 信号②：/sbin/.magisk、/data/adb/magisk 挂载点探测（SVC faccessat） --- */
static int detect_magisk_mountpoint(void) {
    static const char *const PATHS[] = {
        "/sbin/.magisk", "/data/adb/magisk", "/data/adb/magisk.db"
    };
    for (int i = 0; i < 3; i++) {
        if (svc_faccessat(PATHS[i]) == 0) return 1;
    }
    return 0;
}

/* --- 信号③：dex2oat loop mounts（LSPosed 注入特征，SVC 直读） --- */
static int detect_dex2oat_loop(void) {
    static char buf[32768];
    long n = svc_read_file("/proc/self/mountinfo", buf, sizeof(buf));
    if (n <= 0) return 0;
    char *line = buf;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        /* LSPosed 在 /apex 上做 loop 挂载（dex2oat 替换） */
        if (strstr(line, "/apex/com.android.art") && strstr(line, " loop")) return 1;
        if (!nl) break;
        line = nl + 1;
    }
    return 0;
}

/* --- 信号④：magiskd/zygiskd 进程（读 comm 线程名 + SELinux context，SVC 直读） --- */
static int detect_magiskd_process(void) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *de;
    int hit = 0;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        char path[64];
        char buf[256];
        /* 优先读 /proc/<pid>/comm（线程名，Magisk 的 magiskd/zygiskd 在此可见） */
        snprintf(path, sizeof(path), "/proc/%s/comm", de->d_name);
        long n = svc_read_file(path, buf, sizeof(buf));
        if (n > 0) {
            if (strstr(buf, "magiskd") || strstr(buf, "zygiskd") ||
                strstr(buf, "zygisk") || strstr(buf, "ksud") || strstr(buf, "lspd")) {
                hit = 1; break;
            }
        }
        /* 再读 /proc/<pid>/attr/current（SELinux context，u:r:magisk:s0 是 Magisk 专属 domain） */
        snprintf(path, sizeof(path), "/proc/%s/attr/current", de->d_name);
        n = svc_read_file(path, buf, sizeof(buf));
        if (n > 0 && strstr(buf, "magisk")) { hit = 1; break; }
    }
    closedir(d);
    return hit;
}

/* --- 信号⑤：/proc/self/mounts 里的 magisk 字样（SVC 直读） --- */
static int detect_mounts_magisk(void) {
    static char buf[32768];
    long n = svc_read_file("/proc/self/mounts", buf, sizeof(buf));
    if (n <= 0) return 0;
    return strstr(buf, "magisk") ? 1 : 0;
}

/* --- 信号⑥：环境变量 MAGISK_VER_CODE / KSU_VER_CODE（SVC 直读） --- */
static int detect_env_magisk(void) {
    static char buf[4096];
    long n = svc_read_file("/proc/self/environ", buf, sizeof(buf));
    if (n <= 0) return 0;
    if (strstr(buf, "MAGISK_VER_CODE") || strstr(buf, "KSU_VER_CODE") ||
        strstr(buf, "KSU_KERNEL_VER_CODE")) {
        return 1;
    }
    return 0;
}

/* --- 信号⑦：native bridge 非空 或 /data/adb/modules 目录（SVC faccessat） --- */
static int detect_native_bridge_or_modules(void) {
    char v[128];
    if (__system_property_get("ro.dalvik.vm.native.bridge", v) > 0) {
        if (v[0] != '\0' && strcmp(v, "0") != 0 && strcmp(v, "none") != 0) return 1;
    }
    if (svc_faccessat("/data/adb/modules") == 0) return 1;
    return 0;
}

/*
 * full_check()：七类信号各记 1 分，返回命中位图（bit0..bit6）。
 * 评分阈值制：命中 ≥ TAMPER_THRESHOLD 才算"检测到环境异常"。
 */
static int full_check(void) {
    int bitmap = 0;
    if (detect_mountinfo_magisk())        bitmap |= (1 << 0);
    if (detect_magisk_mountpoint())       bitmap |= (1 << 1);
    if (detect_dex2oat_loop())            bitmap |= (1 << 2);
    if (detect_magiskd_process())         bitmap |= (1 << 3);
    if (detect_mounts_magisk())           bitmap |= (1 << 4);
    if (detect_env_magisk())              bitmap |= (1 << 5);
    if (detect_native_bridge_or_modules()) bitmap |= (1 << 6);
    return bitmap;
}

/* 命中位数统计 */
static int popcount(int x) {
    int c = 0;
    while (x) { x &= (x - 1); c++; }
    return c;
}

static int is_tampered(int bitmap) {
    return popcount(bitmap) >= TAMPER_THRESHOLD ? 1 : 0;
}

/* --- 诱饵导出（无意义，干扰用） --- */
void mount_decoy_scan(void) {}
void mount_fold(void) {}
void mount_spin(void) {}

/* --- JNI 桥接 --- */

/* MountGuard.nativeFullCheck() → int 位图（bit0..bit6 对应七类信号） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_MountGuard_nativeFullCheck(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return (jint)full_check();
}

/* MountGuard.nativeIsTampered(bitmap) → int（1=检测到环境异常，0=干净） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_MountGuard_nativeIsTampered(JNIEnv *env, jclass clazz, jint bitmap) {
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
