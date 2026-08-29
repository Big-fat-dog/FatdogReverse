/*
 * 幽冥海 KL11：偷梁换柱——静态 patch 入门。
 *
 * guard(input) 函数：if (input == MAGIC) return 1; else return 0;
 * answer() 函数：return MAGIC;
 *
 * 要求：patch so 让 guard(0) 返回 1（nop 掉比较跳转指令），
 *       然后调用 answer() 拿到答案提交。
 *
 * 标记（真）：Fatdog_tamper  — UTF-16 码元，非 static 非 const 全局存放。
 * 诱饵（假）：Fatdog_temper  — 一字之差陷阱，命中即 403。
 * 设计要点：最小 patch 靶场——只有一个比较指令需要改。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>

/* --- 真标记：Fatdog_tamper（UTF-16LE 码元） --- */
static const jchar MARKER[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067, /* Fatdog */
    0x005F,                                           /* _      */
    0x0074, 0x0061, 0x006D, 0x0070, 0x0065, 0x0072  /* tamper */
};
#define MARKER_LEN 13

/* --- 诱饵：Fatdog_temper（仅一处不同：a→e） --- */
static const jchar DECOY[] = {
    0x0046, 0x0061, 0x0074, 0x0064, 0x006F, 0x0067,
    0x005F,
    0x0074, 0x0065, 0x006D, 0x0070, 0x0065, 0x0072
};
#define DECOY_LEN 13

/* --- 魔数：guard 的比较对象 --- */
#define MAGIC 0x46415444  /* "FADD" in ASCII */

/* --- XOR 常量：answer 的变换因子 --- */
#define XOR_KEY 0x00001337

/*
 * guard(input)：核心比较函数。
 * 这是 patch 靶场——玩家需要在 IDA 中找到这里的 CMP/BEQ 指令，
 * 将条件跳转改为 NOP（或无条件跳转），使函数恒返回 1。
 *
 * ARM64 编译后大致为：
 *   CMP W0, #0x46415444
 *   B.EQ loc_xxx
 *   MOV W0, #0
 *   RET
 * loc_xxx:
 *   MOV W0, #1
 *   RET
 *
 * Patch 方法：将 B.EQ 改为 NOP（0x1F2003D5），或改为 B（无条件跳转）。
 */
int guard(int input) {
    if (input == MAGIC) {
        return 1;
    }
    return 0;
}

/*
 * answer()：返回最终答案（十进制提交）。
 * 答案 = MAGIC ^ XOR_KEY = 0x46415444 ^ 0x00001337 = 0x46414773
 * 十进制 = 1178810227。
 *
 * 这个函数在 IDA 中也很容易定位——返回一个立即数。
 * 玩家可以用 unidbg 直接调用，也可以静态分析读出来。
 */
int answer(void) {
    return MAGIC ^ XOR_KEY;
}

/* --- 诱饵导出：拿 Fatdog_temper 算签名只会换来 403 --- */
void m10_decoy_seal(void) {}
void m10_fold(void) {}
void m10_spin(void) {}

/* --- JNI 桥接 --- */

/* Tu.nativeGuard(input) → int */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Tu_nativeGuard(JNIEnv *env, jclass clazz, jint input) {
    (void)clazz;
    return (jint)guard((int)input);
}

/* Tu.nativeAnswer() → int */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Tu_nativeAnswer(JNIEnv *env, jclass clazz) {
    (void)clazz;
    return (jint)answer();
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    return JNI_VERSION_1_6;
}
