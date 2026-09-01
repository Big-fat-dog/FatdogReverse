/*
 * 幽冥海 KL13：声东击西——反 patch 对抗（CRC 自校验）。
 *
 * 核心思路：guard() 内嵌 CRC32 校验——启动时对 guard 自身代码算 CRC 存入全局变量，
 * 每次调用 check() 时重新算一遍比对。patch 任何指令都会改变 CRC → 校验失败 → 静默返回 0。
 *
 * 解法（三选一）：
 *   ① Frida hook check 强制返回 1（跳过 CRC，最简单）；
 *   ② patch CRC 基线值（IDA 找到 CRC 常量改为 patched 代码的 CRC）；
 *   ③ 完整复刻 CRC 算法 + guard 逻辑 → Python 本地计算（最硬核）。
 *
 * 标记（真）：Fatdog_guard  — UTF-16 码元，非 static 非 const 全局存放。
 * 诱饵（假）：Fatdog_gourd  — 一字之差陷阱，命中即 403。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>

/* --- 真标记：Fatdog_guard（UTF-16LE 码元） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067, /* Fatdog */
    0x005F,                                           /* _      */
    0x0067, 0x0075, 0x0061, 0x0072, 0x0064          /* guard  */
};
#define MARKER_LEN 12

/* --- 诱饵：Fatdog_gourd（a→o） --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0067, 0x006F, 0x0075, 0x0072, 0x0064
};
#define DECOY_LEN 12

/* --- 魔数 --- */
#define MAGIC 0xCAFEBABE

/* --- XOR 常量 --- */
#define XOR_KEY 0x0000DEAD

/* --- CRC32 基线：编译时对 guard 代码段预计算 --- */
/* 简化版：用 XOR 折叠代替完整 CRC32（教学够用） */
static uint32_t crc_baseline = 0;

/*
 * simple_crc32：简易 CRC32（教学版，非标准 polynomial）。
 * 对 data 前 len 字节算 CRC32，用于校验 guard 代码段完整性。
 */
static uint32_t simple_crc32(const uint8_t *data, int len) {
    uint32_t crc = 0xFFFFFFFF;
    int i, j;
    for (i = 0; i < len; i++) {
        crc ^= (uint32_t)data[i];
        for (j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }
    return crc ^ 0xFFFFFFFF;
}

/*
 * init_crc：启动时计算 guard 代码段的 CRC 基线。
 * 这里用 MARKER 数组 + MAGIC 常量模拟代码段指纹（真实场景是对 .text 段算 CRC）。
 * patch 会改变指令字节 → CRC 变化 → 校验失败。
 */
static void init_crc(void) {
    /* 拇指印：MARKER 的字节 + MAGIC 的字节 + XOR_KEY 的字节 */
    uint8_t buf[sizeof(MARKER) + 12];
    int off = 0;
    int i;
    uint32_t v;
    memcpy(buf, MARKER, sizeof(MARKER));
    off += sizeof(MARKER);
    v = MAGIC; memcpy(buf + off, &v, 4); off += 4;
    v = XOR_KEY; memcpy(buf + off, &v, 4); off += 4;
    v = 0x01020304; memcpy(buf + off, &v, 4); off += 4;
    crc_baseline = simple_crc32(buf, off);
}

/*
 * verify_crc：每次 check() 调用时重新计算并比对。
 * 如果 MARKER/MAGIC/XOR_KEY 被改（patch）→ CRC 不匹配 → 返回 0。
 */
static int verify_crc(void) {
    uint8_t buf[sizeof(MARKER) + 12];
    int off = 0;
    int i;
    uint32_t v;
    memcpy(buf, MARKER, sizeof(MARKER));
    off += sizeof(MARKER);
    v = MAGIC; memcpy(buf + off, &v, 4); off += 4;
    v = XOR_KEY; memcpy(buf + off, &v, 4); off += 4;
    v = 0x01020304; memcpy(buf + off, &v, 4); off += 4;
    return simple_crc32(buf, off) == crc_baseline;
}

/*
 * guard(input)：CRC 校验 + 比较双保险。
 * patch 任一环节都会触发连锁反应。
 */
int guard(int input) {
    if (!verify_crc()) return 0;
    if (input == MAGIC) return 1;
    return 0;
}

/*
 * check()：独立校验入口，先过 CRC 再验证 guard 的返回值。
 * Frida 解法：hook check 强制返回 1（跳过两层校验）。
 */
int check(void) {
    if (!verify_crc()) return 0;
    return guard(0); /* 未 patch 时 guard(0)=0，门禁初始关闭 */
}

/* --- 诱饵导出 --- */
void m12_decoy_seal(void) {}
void m12_fold(void) {}
void m12_spin(void) {}

/* --- JNI 桥接 --- */

/* Ap.nativeGuard(input) → int */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Ap_nativeGuard(JNIEnv *env, jclass clazz, jint input) {
    (void)clazz;
    static int inited = 0;
    if (!inited) { init_crc(); inited = 1; }
    return (jint)guard((int)input);
}

/* Ap.nativeCheck() → int */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Ap_nativeCheck(JNIEnv *env, jclass clazz) {
    (void)clazz;
    static int inited = 0;
    if (!inited) { init_crc(); inited = 1; }
    return (jint)check();
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    return JNI_VERSION_1_6;
}
