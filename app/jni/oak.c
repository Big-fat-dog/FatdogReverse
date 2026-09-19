/*
 * 天地秘境·九幽 KL47：深根固蒂——Bootloader 解锁 + 系统属性深检。
 *
 * 与扶桑树的区别：扶桑树 KL21-28 是「检测你有没有在 hook 我（Frida 动态注入）」；
 * 九幽是「检测设备本身是否 root / 解锁 / 被改」。本关考点是系统属性 + 内核启动
 * 参数层的完整性检测——正是银行/支付/风控 SDK 的标配，扶桑树完全未覆盖。
 *
 * 七类信号（每一类真实执行、真实读结果），各记 1 分，命中 ≥ 2 才判定环境异常：
 *   ① ro.boot.verifiedbootstate：orange（已解锁）/ red（验证失败）即命中，green 为锁定正常；
 *   ② ro.boot.vbmeta.device_state / vendor.boot.vbmeta.device_state：unlocked 即命中；
 *   ③ ro.secureboot.lockstate / ro.boot.flash.locked：unlocked / 0 即命中；
 *   ④ 内核启动参数 /proc/cmdline：解析 androidboot.verifiedbootstate=orange、
 *      androidboot.flash.locked=0（内核导出只读信息，setprop 无法伪造，属性层最硬一路）；
 *   ⑤ ro.build.tags=test-keys / ro.build.type=eng|userdebug / ro.debuggable=1
 *      （命中 ≥2 个才记 1 分，单个 debug 属性不单独定罪）；
 *   ⑥ ro.dalvik.vm.native.bridge 非空（Xposed/LSPosed 的 native bridge 特征）；
 *   ⑦ 自定义 ROM 检测：ro.lineage.build.version 存在 或 /system/framework/org.lineageos.*.jar 存在。
 *
 * 破解路线：
 *   ① Magisk/Shamiko 用 resetprop 伪造 boot 属性；
 *   ② hook __system_property_get 过滤；
 *   ③ hook open/read 过滤 /proc/cmdline；
 *   ④ patch so 改判定跳转。
 *
 * 标记（真）：Fatdog_probe  — UTF-16 码元（static const，借 JNI_OnLoad 引用强制保留）。
 * 诱饵（假）：Fatdog_trap   — 一字之差陷阱（probe→trap）。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* --- 真标记：Fatdog_probe（UTF-16LE 码元） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067, /* Fatdog */
    0x005F,                                           /* _      */
    0x0070, 0x0072, 0x006F, 0x0062, 0x0065          /* probe  */
};
#define MARKER_LEN 12

/* --- 诱饵：Fatdog_trap（probe→trap） --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0074, 0x0072, 0x0061, 0x0070
};
#define DECOY_LEN 11

/* 标记留存：防止 --gc-sections 把未引用的 MARKER/DECOY 整体删除 */
static volatile uint32_t g_marker_proof = 0;

/* 判定阈值：七类信号命中 ≥ 2 才判环境异常（评分制，防单点误杀）。 */
#define TAMPER_THRESHOLD 2

/* 直接声明 libc 的 __system_property_get，不走 Java System.getProperty。 */
extern int __system_property_get(const char *name, char *value);

static int prop_equals(const char *name, const char *expect) {
    char v[128];
    if (__system_property_get(name, v) > 0 && strcmp(v, expect) == 0) return 1;
    return 0;
}

static int prop_contains(const char *name, const char *sub) {
    char v[128];
    if (__system_property_get(name, v) > 0 && strstr(v, sub)) return 1;
    return 0;
}

/* --- 信号①：verifiedbootstate（orange/red = 已解锁/验证失败） --- */
static int detect_verifiedbootstate(void) {
    char v[128];
    if (__system_property_get("ro.boot.verifiedbootstate", v) > 0) {
        if (strstr(v, "orange") || strstr(v, "red") || strstr(v, "yellow")) return 1;
    }
    return 0;
}

/* --- 信号②：vbmeta.device_state（unlocked） --- */
static int detect_vbmeta_state(void) {
    if (prop_equals("ro.boot.vbmeta.device_state", "unlocked")) return 1;
    if (prop_equals("vendor.boot.vbmeta.device_state", "unlocked")) return 1;
    return 0;
}

/* --- 信号③：secureboot.lockstate / flash.locked（unlocked/0） --- */
static int detect_lockstate(void) {
    if (prop_equals("ro.secureboot.lockstate", "unlocked")) return 1;
    if (prop_equals("ro.boot.flash.locked", "0")) return 1;
    if (prop_equals("ro.boot.flash.locked", "unlocked")) return 1;
    return 0;
}

/* --- 信号④：内核启动参数 /proc/cmdline --- */
static int detect_cmdline(void) {
    FILE *f = fopen("/proc/cmdline", "r");
    if (!f) return 0;
    char line[2048];
    int hit = 0;
    if (fgets(line, sizeof(line), f)) {
        if (strstr(line, "androidboot.verifiedbootstate=orange")) hit = 1;
        else if (strstr(line, "androidboot.flash.locked=0")) hit = 1;
        else if (strstr(line, "androidboot.vbmeta.device_state=unlocked")) hit = 1;
    }
    fclose(f);
    return hit;
}

/* --- 信号⑤：debug 属性（tags/type/debuggable，命中 ≥2 个才记 1 分） --- */
static int detect_debugprops(void) {
    int score = 0;
    if (prop_contains("ro.build.tags", "test-keys")) score++;
    if (prop_contains("ro.build.type", "eng")) score++;
    if (prop_contains("ro.build.type", "userdebug")) score++;
    char v[128];
    if (__system_property_get("ro.debuggable", v) > 0 && v[0] == '1') score++;
    return score >= 2 ? 1 : 0;
}

/* --- 信号⑥：native bridge（Xposed/LSPosed 特征） --- */
static int detect_native_bridge(void) {
    char v[128];
    if (__system_property_get("ro.dalvik.vm.native.bridge", v) > 0) {
        /* "0" / "none" / 空 = 未启用原生桥（部分 ROM 默认设 "0"），不能算命中；
         * 只有真正的 .so 文件名（libriruloader.so / libzygisk.so 等）才算 Xposed/LSPosed 注入。 */
        if (v[0] != '\0' && strcmp(v, "0") != 0 && strcmp(v, "none") != 0) {
            return 1;
        }
    }
    return 0;
}

/* --- 信号⑦：自定义 ROM（LineageOS 等） --- */
static int detect_custom_rom(void) {
    char v[128];
    if (__system_property_get("ro.lineage.build.version", v) > 0) return 1;
    /* 特征 jar 文件 */
    static const char *const ROM_JARS[] = {
        "/system/framework/org.lineageos.platform.jar",
        "/system/framework/org.lineageos.hardware.jar"
    };
    for (int i = 0; i < 2; i++) {
        FILE *f = fopen(ROM_JARS[i], "r");
        if (f) { fclose(f); return 1; }
    }
    return 0;
}

/*
 * full_check()：七类信号各记 1 分，返回命中位图（bit0..bit6）。
 * 评分阈值制：命中 ≥ TAMPER_THRESHOLD 才算"检测到环境异常"。
 */
static int full_check(void) {
    int bitmap = 0;
    if (detect_verifiedbootstate()) bitmap |= (1 << 0);
    if (detect_vbmeta_state())     bitmap |= (1 << 1);
    if (detect_lockstate())        bitmap |= (1 << 2);
    if (detect_cmdline())          bitmap |= (1 << 3);
    if (detect_debugprops())       bitmap |= (1 << 4);
    if (detect_native_bridge())    bitmap |= (1 << 5);
    if (detect_custom_rom())       bitmap |= (1 << 6);
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
void boot_decoy_scan(void) {}
void boot_fold(void) {}
void boot_spin(void) {}

/* --- JNI 桥接 --- */

/* BootGuard.nativeFullCheck() → int 位图（bit0..bit6 对应七类信号） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_BootGuard_nativeFullCheck(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return (jint)full_check();
}

/* BootGuard.nativeIsTampered(bitmap) → int（1=检测到环境异常，0=干净） */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_BootGuard_nativeIsTampered(JNIEnv *env, jclass clazz, jint bitmap) {
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
