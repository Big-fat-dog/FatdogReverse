/**
 * tide.c — 天机阁 KL29 暗流涌动（TLV 二进制协议）
 * 双重检测：TLV 帧 magic 校验 + ptrace 反附加
 * 判定逻辑：OR（任一触发即判定）
 * SEED = 20280723
 * Flag: FLAG_18_KL29{surging_undercurrents}
 */

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>

/* ============================================================
 * 诱饵标记：Fatdog_surge（真）/ Fatdog_swell（假）
 * ============================================================ */
static const char REAL_MARK[]  = "Fatdog_surge";
static const char FAKE_MARK[]  = "Fatdog_swell";

/* ============================================================
 * TLV 帧构建（Type-Length-Value）
 * ============================================================ */
typedef struct {
    uint32_t type;
    uint32_t length;
    unsigned char value[];
} __attribute__((packed)) TlvFrame;

#define TLV_MAGIC   0x4644544C  /* "FDTL" */
#define TLV_TYPE_REQ 0x0001
#define TLV_TYPE_RSP 0x0002

static int build_tlv_frame(unsigned char *out, int *out_len,
                           uint32_t page, uint64_t ts) {
    /* 构建 TLV 请求帧：magic(4) + type(4) + length(4) + page(4) + ts(8) */
    unsigned char buf[32];
    int off = 0;

    /* magic */
    uint32_t magic = TLV_MAGIC;
    memcpy(buf + off, &magic, 4); off += 4;
    /* type */
    uint32_t type = TLV_TYPE_REQ;
    memcpy(buf + off, &type, 4); off += 4;
    /* length = 12 (page + ts) */
    uint32_t length = 12;
    memcpy(buf + off, &length, 4); off += 4;
    /* page */
    memcpy(buf + off, &page, 4); off += 4;
    /* ts */
    memcpy(buf + off, &ts, 8); off += 8;

    memcpy(out, buf, off);
    *out_len = off;
    return 0;
}

/* ============================================================
 * 检测①：TLV magic 校验（检测是否被篡改）
 * ============================================================ */
static int detect_tlv_magic(void) {
    unsigned char frame[32];
    int len;
    build_tlv_frame(frame, &len, 1, 20280723);

    /* 检查 magic 是否正确 */
    uint32_t magic;
    memcpy(&magic, frame, 4);
    if (magic != TLV_MAGIC) {
        return 1;  /* 被篡改 */
    }
    return 0;
}

/* ============================================================
 * 检测②：ptrace 反附加
 * ============================================================ */
static int detect_ptrace(void) {
    long result = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (result == -1) {
        return 1;
    }
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
    return 0;
}

/* ============================================================
 * 综合检测（OR 判定）
 * ============================================================ */
static int detect_frida(void) {
    return detect_tlv_magic() || detect_ptrace();
}

/* ============================================================
 * 答案计算
 * ============================================================ */
static const char* compute_answer(void) {
    static char result[33];
    unsigned int seed = 20280723;
    unsigned int hash = seed;
    hash = hash * 1103515245u + 12345u;
    hash ^= hash << 13;
    hash ^= hash >> 17;
    hash ^= hash << 5;
    unsigned int h2 = seed;
    h2 = h2 * 214013u + 2531011u;
    hash ^= h2;
    for (int i = 0; i < 32; i++) {
        result[i] = "0123456789abcdef"[(hash >> (i % 4 * 4)) & 0xf];
        hash = hash * 1664525u + 1013904223u;
    }
    result[32] = '\0';
    return result;
}

/* ============================================================
 * 状态详情
 * ============================================================ */
static const char* compute_status(void) {
    static char buf[512];
    int tlv = detect_tlv_magic();
    int ptr = detect_ptrace();

    snprintf(buf, sizeof(buf),
        "=== 暗流涌动 ===\n"
        "TLV magic:    %s\n"
        "ptrace检测:   %s\n"
        "综合判定(OR): %s\n\n"
        "标记A: %s\n标记B: %s",
        tlv ? "异常" : "正常",
        ptr ? "检出" : "安全",
        detect_frida() ? "检出" : "安全",
        REAL_MARK, FAKE_MARK);
    return buf;
}

/* ============================================================
 * JNI 导出
 * ============================================================ */

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Ak29_nativeTlvMagic(JNIEnv *e, jclass c) {
    return detect_tlv_magic();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Ak29_nativePtrace(JNIEnv *e, jclass c) {
    return detect_ptrace();
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Ak29_nativeFridaDetect(JNIEnv *e, jclass c) {
    return detect_frida();
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Ak29_nativeAnswer(JNIEnv *e, jclass c) {
    return (*e)->NewStringUTF(e, compute_answer());
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Ak29_nativeStatus(JNIEnv *e, jclass c) {
    return (*e)->NewStringUTF(e, compute_status());
}
