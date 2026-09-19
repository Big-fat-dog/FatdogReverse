/*
 * 天地秘境·九幽 KL49：盘根错节——新一代 root（KernelSU/APatch）检测 + Play Integrity 本地仿真。
 *
 * 考点：Magisk 之外的「新一代 root 方案」——KernelSU（内核态、不依赖 boot 镜像 patch）、
 * APatch（内核补丁）。它们比 Magisk 更难检测：su 文件在 /data/adb/ksu、无 magiskd 进程、
 * 不挂 magisk tmpfs。检测方靠「内核版本串含 -KernelSU / -APatch 特征」「/data/adb/ksu、
 * /data/adb/ap 目录」「KSU_VER_CODE 环境变量」来识别。本关叠加 Play Integrity 本地仿真。
 *
 * 六类信号（全部 SVC 直接系统调用读取，穿透 Shamiko/Kitsune 的 libc hook；读 /proc 文件
 * 用循环 read），各记 1 分，命中 ≥ 2 才判定环境异常：
 *   ① 内核版本串：SVC uname 读 version/release，搜索 KernelSU / KSU / APatch / kpatch；
 *   ② KernelSU/APatch 目录：SVC faccessat 探 /data/adb/ksu、/data/adb/ksud、/data/adb/ap、/data/adb/apd；
 *   ③ 环境变量：SVC 循环读 /proc/self/environ，搜 KSU_VER_CODE / KSU_KERNEL_VER_CODE / APATCH_VER；
 *   ④ 挂载点：SVC 循环读 /proc/self/mounts，搜 ksu / ap 挂载；
 *   ⑤ 仿 Play Integrity token：内置结构仿真 token（含 deviceRecognition 字段与
 *      MEETS_BASIC_INTEGRITY/MEETS_DEVICE_INTEGRITY 标志位），校验其设备状态位是否被篡改
 *      （本地仿真：真实 PI 依赖 GMS+云端 verdict，离线靶场无法复现，练的是读懂 token 结构+绕过本地校验）；
 *   ⑥ Magisk 兜底：/data/adb/magisk 目录（SVC faccessat）或 /proc/self/mounts 含 magisk。
 *
 * 破解路线：
 *   ① KernelSU/APatch 的 unmount + ZygiskNext 隐藏 ksu/ap 目录与内核特征；
 *   ② hook 检测函数出口返回 0 或 patch so（SVC 直读无法 libc hook 拦截）；
 *   ③ 静态读懂仿 token 结构，patch so 让校验恒真。
 *
 * 标记（真）：Fatdog_attest  — UTF-16 码元（static const，借 JNI_OnLoad 引用强制保留）。
 * 诱饵（假）：Fatdog_attests — 一字之差陷阱（attest→attests）。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef __aarch64__
#include <sys/syscall.h>
#endif

/* --- 真标记：Fatdog_attest（UTF-16LE 码元） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067, /* Fatdog */
    0x005F,                                           /* _      */
    0x0061, 0x0074, 0x0074, 0x0065, 0x0073, 0x0074  /* attest */
};
#define MARKER_LEN 13

/* --- 诱饵：Fatdog_attests（attest→attests） --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0061, 0x0074, 0x0074, 0x0065, 0x0073, 0x0074, 0x0073
};
#define DECOY_LEN 14

/* 标记留存：防止 --gc-sections 把未引用的 MARKER/DECOY 整体删除 */
static volatile uint32_t g_marker_proof = 0;

/* 判定阈值：六类信号命中 ≥ 2 才判环境异常（评分制，防单点误杀）。 */
#define TAMPER_THRESHOLD 2

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

/* SVC uname：读内核版本串（KernelSU/APatch 会在内核版本串加 -KernelSU / -APatch 标记） */
static int svc_uname(char *buf, size_t cap) {
#ifdef __aarch64__
    /* 用 SVC 直调 uname 系统调用（__NR_uname），写入 struct utsname */
    struct { char sysname[65]; char nodename[65]; char release[65];
             char version[65]; char machine[65]; char domainname[65]; } uts;
    register long x8 __asm__("x8") = __NR_uname;
    register long x0 __asm__("x0") = (long)&uts;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    if (x0 != 0) return -1;
    snprintf(buf, cap, "%s %s %s", uts.sysname, uts.release, uts.version);
    return 0;
#else
    /* host 回退：直接返回空（host 语法体检用） */
    buf[0] = '\0';
    return -1;
#endif
}

/* svc_read_file：循环 read 读全 /proc 文件（穿透 hook + 读完整） */
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

/* --- 信号①：内核版本串（SVC uname） --- */
static int detect_kernel_su(void) {
    char buf[256];
    if (svc_uname(buf, sizeof(buf)) != 0) return 0;
    if (strstr(buf, "KernelSU") || strstr(buf, "KSU") ||
        strstr(buf, "APatch") || strstr(buf, "kpatch") || strstr(buf, "-kernelsu")) {
        return 1;
    }
    return 0;
}

/* --- 信号②：KernelSU/APatch 目录（SVC faccessat） --- */
static int detect_ksu_dir(void) {
    static const char *const PATHS[] = {
        "/data/adb/ksu", "/data/adb/ksud", "/data/adb/ap", "/data/adb/apd",
        "/data/adb/ksu/modules.img", "/data/adb/ksud"
    };
    for (int i = 0; i < 6; i++) {
        if (svc_faccessat(PATHS[i]) == 0) return 1;
    }
    return 0;
}

/* --- 信号③：环境变量 KSU_VER_CODE（SVC 循环读） --- */
static int detect_ksu_env(void) {
    static char buf[4096];
    long n = svc_read_file("/proc/self/environ", buf, sizeof(buf));
    if (n <= 0) return 0;
    if (strstr(buf, "KSU_VER_CODE") || strstr(buf, "KSU_KERNEL_VER_CODE") ||
        strstr(buf, "APATCH_VER") || strstr(buf, "MAGISK_VER_CODE")) {
        return 1;
    }
    return 0;
}

/* --- 信号④：挂载点 ksu/ap（SVC 循环读 /proc/self/mounts） --- */
static int detect_ksu_mounts(void) {
    static char buf[32768];
    long n = svc_read_file("/proc/self/mounts", buf, sizeof(buf));
    if (n <= 0) return 0;
    char *save = NULL;
    char *line = strtok_r(buf, "\n", &save);
    while (line) {
        if (strstr(line, "ksu") || strstr(line, "apd") || strstr(line, "apatch")) return 1;
        line = strtok_r(NULL, "\n", &save);
    }
    return 0;
}

/* --- 信号⑤：仿 Play Integrity token 校验（本地仿真） --- */
/*
 * 结构仿真的 token：真实 Play Integrity 的 verdict token 含 deviceRecognition 字段
 * （MEETS_BASIC_INTEGRITY / MEETS_DEVICE_INTEGRITY / MEETS_STRONG_INTEGRITY 标志位）。
 * 本关内置一段仿真 token（16 字节魔数 + 设备状态位），校验其"设备状态位"是否被篡改。
 * 明文为本地仿真（离线靶场无 GMS+云端），练的是读懂 token 结构 + 绕过本地校验。
 */
static const unsigned char PI_TOKEN[] = {
    0x46, 0x44, 0x50, 0x49, 0x00, 0x01, 0x02, 0x03,  /* "FDPI" 魔数（0-3）+ 版本号（4-7） */
    0x00, 0x00, 0x00, 0x00,                          /* 设备状态位（8-11，全 0 = 通过 BASIC+DEVICE） */
    0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4f, 0x6b   /* "DeviceOk"（12-19） */
};
#define PI_TOKEN_LEN 20

static int detect_pi_token(void) {
    /* 校验 token 魔数 + 设备状态位是否被篡改（本地仿真校验） */
    if (PI_TOKEN[0] != 0x46 || PI_TOKEN[1] != 0x44 ||
        PI_TOKEN[2] != 0x50 || PI_TOKEN[3] != 0x49) return 1; /* 魔数被改 = 被 patch */
    /* 设备状态位（索引 8-11）：非全 0 表示设备未通过完整性（本关仿真"被篡改"） */
    for (int i = 8; i < 12; i++) {
        if (PI_TOKEN[i] != 0) return 1;
    }
    return 0;
}

/* --- 信号⑥：Magisk 兜底（/data/adb/magisk 或 mounts 含 magisk） --- */
static int detect_magisk_fallback(void) {
    if (svc_faccessat("/data/adb/magisk") == 0) return 1;
    static char buf[32768];
    long n = svc_read_file("/proc/self/mounts", buf, sizeof(buf));
    if (n > 0 && strstr(buf, "magisk")) return 1;
    return 0;
}

/*
 * full_check()：六类信号各记 1 分，返回命中位图（bit0..bit5）。
 * 评分阈值制：命中 ≥ TAMPER_THRESHOLD 才算"检测到环境异常"。
 */
static int full_check(void) {
    int bitmap = 0;
    if (detect_kernel_su())       bitmap |= (1 << 0);
    if (detect_ksu_dir())         bitmap |= (1 << 1);
    if (detect_ksu_env())         bitmap |= (1 << 2);
    if (detect_ksu_mounts())      bitmap |= (1 << 3);
    if (detect_pi_token())        bitmap |= (1 << 4);
    if (detect_magisk_fallback()) bitmap |= (1 << 5);
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
void kernel_decoy_scan(void) {}
void kernel_fold(void) {}
void kernel_spin(void) {}

/* --- JNI 桥接 --- */

/* KernelGuard.nativeFullCheck() → int 位图（bit0..bit5 对应六类信号） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_KernelGuard_nativeFullCheck(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return (jint)full_check();
}

/* KernelGuard.nativeIsTampered(bitmap) → int（1=检测到环境异常，0=干净） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_KernelGuard_nativeIsTampered(JNIEnv *env, jclass clazz, jint bitmap) {
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
