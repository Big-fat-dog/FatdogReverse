#include <jni.h>

// ============================================================================
// 昆仑 KL1：山门 —— unidbg 最小骨架练习
//   导出函数 kl_gate(seed)：xorshift32 七轮雪崩后返回。
//   玩家解包取出 libkunlun1.so，在 PC 上用 unidbg 调用即可得答案；
//   App 本地调用同一函数比对（纯本地提交模式）。
// ============================================================================

static unsigned int kl_xorshift(unsigned int x) {
    int i;
    for (i = 0; i < 7; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
    }
    return x;
}

JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Ku1_klGate(JNIEnv *env, jclass clazz, jint seed) {
    (void) env; (void) clazz;
    return (jint) kl_xorshift((unsigned int) seed ^ 0x4B554E4Cu /* "KUNL" */);
}
