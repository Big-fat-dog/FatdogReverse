/*
 * 幽冥海 KL13：声东击西——反 patch 对抗（真实代码段 CRC 自校验）。
 *
 * 核心思路：guard() 的机器码前 KL13_GUARD_CRC_WINDOW 字节在编译期由
 * tools/gen_code_crc_baselines.py 从 NDK 产物里按 ABI 烘焙出真实 CRC-32
 * 基线（kl13_crc_baseline.h，.rodata 里的全局常量）。运行时 verify_crc()
 * 重新对 guard 代码段算 CRC 与基线比对：patch 任何指令都会改变 CRC →
 * 校验失败 → 静默返回 0。基线不是运行时用同一份常量自算的，而是编译期
 * 真实代码指纹，patch 后必须同步改基线才能通过。
 *
 * 解法（三选一）：
 *   ① Frida hook check 强制返回 1（不改字节，跳过 CRC，最简单）；
 *   ② patch 指令后同步 patch .rodata 里的 kGuardCrcBaseline
 *      （IDA 找到该常量改为 patched 代码的 CRC）；
 *   ③ 完整复刻 CRC 算法 + guard 逻辑 → Python 本地计算（最硬核）。
 *
 * 标记（真）：Fatdog_guard  — UTF-16 码元，非 static 非 const 全局存放。
 * 诱饵（假）：Fatdog_gourd  — 一字之差陷阱，命中即 403。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include "kl13_crc_baseline.h"

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

/* CRC-32 基线：由独立翻译单元 kl13_baseline.c 提供（编译期烘焙值）。 */
extern const uint32_t kGuardCrcBaseline;

/* 前置声明：verify_crc 需要取 guard 的函数地址做代码窗口校验 */
int guard(int input);

/*
 * crc32_code：标准 CRC-32（多项式 0xEDB88320，init/final XOR 0xFFFFFFFF），
 * 与 Python zlib.crc32 一致，保证烘焙脚本与运行时算法完全相同。
 */
static uint32_t crc32_code(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    size_t i;
    int b;
    for (i = 0; i < len; i++) {
        crc ^= (uint32_t)data[i];
        for (b = 0; b < 8; b++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

/*
 * verify_crc：对 guard 起始的代码窗口重新算 CRC 并与编译期基线比对。
 * patch 窗口内任何指令（guard/check/诱饵/JNI 入口）都会触发不匹配。
 */
static int verify_crc(void) {
    const uint8_t *code = (const uint8_t *)(uintptr_t)&guard;
    return crc32_code(code, KL13_GUARD_CRC_WINDOW) == kGuardCrcBaseline;
}

/*
 * guard(input)：代码段 CRC 校验 + 比较双保险。
 * 填充循环仅用于保证 guard 代码体足够长（代码窗口真实覆盖本函数机器码），
 * 结果不参与判定。patch 任一环节都会改变窗口字节 → CRC 失败 → 返回 0。
 */
int guard(int input) {
    if (!verify_crc()) return 0;

    volatile uint32_t a = (uint32_t)input;
    volatile uint32_t b = MAGIC;
    volatile uint32_t c = XOR_KEY;
    for (int i = 0; i < 64; i++) {
        a = (a ^ (uint32_t)i) * 2654435761u;
        b = (b >> 5) | (b << 27);
        c = c * 1664525u + 1013904223u;
        a += b ^ c;
    }
    (void)a; (void)b; (void)c;

    return input == MAGIC ? 1 : 0;
}

/*
 * check()：独立校验入口，先过 CRC 再验证 guard 的返回值。
 * 未 patch 时 guard(0)=0，门禁初始关闭；Frida hook check 可强制返回 1。
 */
int check(void) {
    return guard(0);
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
    (void)env;
    return (jint)guard((int)input);
}

/* Ap.nativeCheck() → int */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Ap_nativeCheck(JNIEnv *env, jclass clazz) {
    (void)clazz;
    (void)env;
    return (jint)check();
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    return JNI_VERSION_1_6;
}
