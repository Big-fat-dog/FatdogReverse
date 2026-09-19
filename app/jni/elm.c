/*
 * 天地秘境·九幽 KL46：落叶归根——Root 检测与绕过（多层环境检测入门）。
 *
 * 核心思路：模拟真实 App（RootBeer / Catched 基础层）的多维环境检测。
 * 把"是否 root / 是否被 hook"拆成 7 类信号，每类记 1 分，命中 ≥ 3 才判定
 * 环境异常（评分阈值制，不单点定罪——debug 包 ro.debuggable 恒 1、模拟器
 * 自带 su 这类单点信号单独命中不判死，避免误杀正常训练机）。
 *
 * 七类信号（每一类都真实执行、真实读结果，Frida 才 hook 得到、Magisk 才藏得掉）：
 *   ① SU 文件：libc access() 探测 12+ 个常见 su 路径；
 *   ② Magisk 文件：libc access() 探测 /data/adb/magisk、/sbin/.magisk 等；
 *   ③ 高危包名：读 /proc/self/maps 里是否出现 magisk/supersu/superuser 等包路径；
 *   ④ 系统属性：__system_property_get 直接读 ro.build.tags/ro.build.type/ro.debuggable；
 *   ⑤ SELinux：读 /proc/self/attr/current 是否 permissive；
 *   ⑥ 挂载点：读 /proc/mounts 检查 /system 是否 rw 挂载；
 *   ⑦ SVC 交叉验证（arm64）：用内联 SVC #0 直连内核再探 su 路径，若 SVC 探到 su、
 *      而 libc access 探不到，说明 libc 的 access 已被 hook 篡改——反 hook 检测信号。
 *
 * 破解路线：
 *   ① Frida hook __system_property_get / access / stat 过滤；
 *   ② Magisk DenyList / Shamiko 隐藏 su 与 magisk 文件；
 *   ③ Xposed 模块拦截 java.io.File.exists()；
 *   ④ patch so：把判定阈值相关跳转改掉（BNE→BEQ）。
 *
 * 标记（真）：Fatdog_leaf   — UTF-16 码元（static const，借 JNI_OnLoad 引用强制保留）。
 * 诱饵（假）：Fatdog_leafy  — 一字之差陷阱（leaf→leafy）。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __aarch64__
#include <sys/syscall.h>
#endif

/* --- 真标记：Fatdog_leaf（UTF-16LE 码元） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067, /* Fatdog */
    0x005F,                                           /* _      */
    0x006C, 0x0065, 0x0061, 0x0066                  /* leaf   */
};
#define MARKER_LEN 11

/* --- 诱饵：Fatdog_leafy（leaf→leafy） --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x006C, 0x0065, 0x0061, 0x0066, 0x0079
};
#define DECOY_LEN 12

/* 标记留存：防止 --gc-sections 把未引用的 MARKER/DECOY 整体删除 */
static volatile uint32_t g_marker_proof = 0;

/* 判定阈值：七类信号命中 ≥ 3 才判 Root（评分制，防单点误杀）。 */
#define ROOT_THRESHOLD 3

/*
 * libc_access：走 libc 的 access（Frida 可 hook GOT/PLT 拦截）。
 * svc_access：arm64 用 SVC #0 直接进内核（绕过 libc hook）；其它 ABI 回退 libc。
 * 两者返回值语义一致：0 = 存在/可访问，-1 = 不存在/不可访问。
 * 交叉验证：若 svc_access 探到 su 存在、libc_access 却探不到，说明 libc 被 hook 篡改了结果。
 */
static int libc_access(const char *path) {
    return access(path, 0);
}

static int svc_access(const char *path) {
#ifdef __aarch64__
    register long x8 __asm__("x8") = __NR_faccessat;
    register long x0 __asm__("x0") = (long)(-100); /* AT_FDCWD */
    register long x1 __asm__("x1") = (long)path;
    register long x2 __asm__("x2") = 0;            /* mode 0 = 仅存在性检查 */
    register long x3 __asm__("x3") = 0;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
                     : "memory");
    return (int)x0;
#else
    return access(path, 0);
#endif
}

/* --- 信号①：SU 文件检测（走 libc，可被 hook 拦截） --- */
static const char *const SU_PATHS[] = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
    "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
    "/system/sd/xbin/su", "/system/bin/failsafe/su", "/system/usr/we-need-root/su",
    "/system/xbin/which", "/system/app/Superuser.apk",
    "/system/xbin/daemonsu", "/vendor/bin/su"
};
#define SU_PATH_COUNT ((int)(sizeof(SU_PATHS) / sizeof(SU_PATHS[0])))

static int detect_su_files(void) {
    for (int i = 0; i < SU_PATH_COUNT; i++) {
        if (libc_access(SU_PATHS[i]) == 0) return 1;
    }
    return 0;
}

/* --- 信号⑦：SVC 交叉验证（检测 libc access 是否被 hook 篡改） --- */
static int detect_svc_divergence(void) {
    for (int i = 0; i < SU_PATH_COUNT; i++) {
        int via_libc = libc_access(SU_PATHS[i]);
        int via_svc  = svc_access(SU_PATHS[i]);
        /* SVC 直连看到 su 存在，但 libc access 却说没有 → libc 被 hook 拦截 */
        if (via_svc == 0 && via_libc != 0) return 1;
    }
    return 0;
}

/* --- 信号②：Magisk 文件检测 --- */
static const char *const MAGISK_PATHS[] = {
    "/data/adb/magisk", "/data/adb/magisk.db", "/sbin/.magisk",
    "/cache/magisk.log", "/data/adb/modules", "/data/adb/magisk/busybox"
};
#define MAGISK_PATH_COUNT ((int)(sizeof(MAGISK_PATHS) / sizeof(MAGISK_PATHS[0])))

static int detect_magisk_files(void) {
    for (int i = 0; i < MAGISK_PATH_COUNT; i++) {
        if (libc_access(MAGISK_PATHS[i]) == 0) return 1;
    }
    return 0;
}

/* --- 信号③：高危包名检测（读 /proc/self/maps） --- */
static int detect_risky_packages(void) {
    static const char *const PKG[] = {
        "com.topjohnwu.magisk", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.kingroot.kinguser"
    };
    const int n = (int)(sizeof(PKG) / sizeof(PKG[0]));
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    int hit = 0;
    while (fgets(line, sizeof(line), f)) {
        for (int i = 0; i < n; i++) {
            if (strstr(line, PKG[i])) { hit = 1; break; }
        }
        if (hit) break;
    }
    fclose(f);
    return hit;
}

/* --- 信号④：系统属性检测（__system_property_get 直接读） --- */
/* 直接声明 libc 的 __system_property_get，不走 Java System.getProperty。 */
extern int __system_property_get(const char *name, char *value);

static int detect_sysprops(void) {
    char v[64];
    int score = 0;
    /* test-keys：官方签名应是 release-keys */
    if (__system_property_get("ro.build.tags", v) > 0 && strstr(v, "test-keys")) score++;
    /* eng / userdebug：非 user 构建 */
    if (__system_property_get("ro.build.type", v) > 0 && strstr(v, "eng")) score++;
    if (__system_property_get("ro.build.type", v) > 0 && strstr(v, "userdebug")) score++;
    /* ro.debuggable=1 */
    if (__system_property_get("ro.debuggable", v) > 0 && v[0] == '1') score++;
    /* 命中 ≥2 个属性才记 1 分（单个 debug 属性不单独定罪） */
    return score >= 2 ? 1 : 0;
}

/* --- 信号⑤：SELinux 状态检测 --- */
static int detect_selinux(void) {
    FILE *f = fopen("/proc/self/attr/current", "r");
    if (!f) return 0;
    char line[128];
    int hit = 0;
    if (fgets(line, sizeof(line), f)) {
        if (strstr(line, "permissive")) hit = 1;
    }
    fclose(f);
    return hit;
}

/* --- 信号⑥：挂载点 rw 检测 --- */
static int detect_mount_rw(void) {
    FILE *f = fopen("/proc/mounts", "r");
    if (!f) return 0;
    char line[512];
    int hit = 0;
    while (fgets(line, sizeof(line), f)) {
        /* 行格式：device mountpoint fstype options ... */
        /* 若挂载点 /system 且 options 含 rw 则命中 */
        if (strstr(line, " /system ") && strstr(line, "rw,")) {
            hit = 1;
            break;
        }
    }
    fclose(f);
    return hit;
}

/*
 * full_check()：七类信号各记 1 分，返回命中位图（bit0..bit6）。
 * 评分阈值制：命中 ≥ ROOT_THRESHOLD 才算"检测到 Root"。
 * 返回的位图供 Java 侧逐项渲染（玩家能看见"还差哪几层没绕过"）。
 */
static int full_check(void) {
    int bitmap = 0;
    if (detect_su_files())        bitmap |= (1 << 0);
    if (detect_magisk_files())    bitmap |= (1 << 1);
    if (detect_risky_packages())  bitmap |= (1 << 2);
    if (detect_sysprops())        bitmap |= (1 << 3);
    if (detect_selinux())         bitmap |= (1 << 4);
    if (detect_mount_rw())        bitmap |= (1 << 5);
    /* 第 7 路（bit6）：SVC 交叉验证——SVC 直连探到 su、libc access 却探不到，
     * 说明 libc 的 access 被 hook 篡改（反 hook 检测信号，独立计分）。 */
    if (detect_svc_divergence())  bitmap |= (1 << 6);
    return bitmap;
}

/* 命中位数统计 */
static int popcount(int x) {
    int c = 0;
    while (x) { x &= (x - 1); c++; }
    return c;
}

/*
 * is_rooted(bitmap)：评分阈值判定。
 * 命中数 ≥ ROOT_THRESHOLD → 判定环境异常（返回 1），否则 0。
 */
static int is_rooted(int bitmap) {
    return popcount(bitmap) >= ROOT_THRESHOLD ? 1 : 0;
}

/* --- 诱饵导出（无意义，干扰用） --- */
void root_decoy_scan(void) {}
void root_fold(void) {}
void root_spin(void) {}

/* --- JNI 桥接 --- */

/* RootSentinel.nativeFullCheck() → int 位图（bit0..bit6 对应七类信号） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_RootSentinel_nativeFullCheck(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return (jint)full_check();
}

/* RootSentinel.nativeIsRooted(bitmap) → int（1=检测到 Root，0=干净） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_RootSentinel_nativeIsRooted(JNIEnv *env, jclass clazz, jint bitmap) {
    (void)env; (void)clazz;
    return (jint)is_rooted((int)bitmap);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    /* 标记留存：对真/诱饵标记做校验和写入 volatile 全局，强制其保留在二进制中 */
    uint32_t mp = 0x5A5A5A5Au;
    for (int i = 0; i < MARKER_LEN; i++) mp ^= ((uint32_t)MARKER[i] << (i & 7));
    for (int i = 0; i < DECOY_LEN;  i++) mp ^= ((uint32_t)DECOY[i]  << (i & 7));
    g_marker_proof = mp;
    return JNI_VERSION_1_6;
}
