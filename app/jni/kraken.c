/*
 * 幽冥海 KL12：移花接木——动态 patch（Frida hook）入门。
 *
 * 核心思路：seal() 内嵌常量 0x1337CAFE，check() 校验它。
 * 但 Frida 只需一行 hook seal 强制返回正确值即可——这正是本关要教的。
 *
 * 标记（真）：Fatdog_forge  — UTF-16 码元，非 static 非 const 全局存放。
 * 诱饵（假）：Fatdog_forgo  — 一字之差陷阱，命中即 403。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>

/* --- 真标记：Fatdog_forge（UTF-16LE 码元） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067, /* Fatdog */
    0x005F,                                           /* _      */
    0x0066, 0x006F, 0x0072, 0x0067, 0x0065          /* forge  */
};
#define MARKER_LEN 12

/* --- 诱饵：Fatdog_forgo（e→o） --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0066, 0x006F, 0x0072, 0x0067, 0x006F
};
#define DECOY_LEN 12

/* 标记留存：防止 --gc-sections 把未引用的 MARKER/DECOY 整体删除（题解声称它们躺在 so 里，必须真保留） */
static volatile uint32_t g_marker_proof = 0;

/* --- 魔数：seal 内嵌常量 --- */
#define SEAL_MAGIC 0x1337CAFE

/* --- XOR 常量：answer 的变换因子 --- */
#define XOR_KEY 0x0000BEEF

/*
 * seal()：内嵌常量，未 hook 时返回错误值 0x13377411，hook 后由 Frida 强制返回真值 0x1337CAFE。
 *
 * Frida 解法（本关主解）：
 *   Interceptor.attach(Module.findExportByName("libkraken.so","seal"), {
 *     onLeave: function(r) { r.replace(ptr(0x1337CAFE)); }
 *   });
 *   一行搞定——hook 返回值比改二进制容易得多。
 */
int seal(void) {
    return SEAL_MAGIC ^ XOR_KEY; /* 未 hook 时返回 0x13377411，check 保持关闭 */
}

/*
 * check(val)：校验 seal 的返回值。
 * 静态 patch 难点：check 里也有一处比较，即使改了 seal 还要改 check。
 * 但 Frida 只需 hook seal，check 自然通过——这就是动态 patch 的优势。
 */
int check(int val) {
    if (val == SEAL_MAGIC) {
        return 1;
    }
    return 0;
}

/* --- 诱饵导出 --- */
void m11_decoy_seal(void) {}
void m11_fold(void) {}
void m11_spin(void) {}

/* --- JNI 桥接 --- */

/* Uk.nativeSeal() → int */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Uk_nativeSeal(JNIEnv *env, jclass clazz) {
    (void)clazz;
    return (jint)seal();
}

/* Uk.nativeCheck(val) → int */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Uk_nativeCheck(JNIEnv *env, jclass clazz, jint val) {
    (void)clazz;
    return (jint)check((int)val);
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
