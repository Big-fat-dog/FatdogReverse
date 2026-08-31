/**
 * loom.c — 天机阁 KL30 天机织锦（Protobuf 二进制协议）
 *
 * 协议：Protobuf 编码请求（PageRequest）→ 服务端返回 Protobuf（PageResponse + HMAC）
 * 破解路线：抓包 hex → protoc --decode_raw → 重建 .proto → Python 复刻
 * SEED = 20280724
 * Flag: FLAG_18_KL30{heavenly_loom}
 */

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* ============================================================
 * 诱饵标记：Fatdog_weave（真）/ Fatdog_knit（假）
 * ============================================================ */
static const char REAL_MARK[] = "Fatdog_weave";
static const char FAKE_MARK[] = "Fatdog_knit";

#define SEED30 20280724

/* ============================================================
 * Protobuf 手写编码（wire format）
 * ============================================================ */

/* varint 编码：返回写入字节数 */
static int encode_varint(uint8_t *out, uint64_t value) {
    int i = 0;
    while (value > 0x7F) {
        out[i++] = (uint8_t)(value & 0x7F) | 0x80;
        value >>= 7;
    }
    out[i++] = (uint8_t)(value & 0x7F);
    return i;
}

/* 编码 field varint（tag + value） */
static int encode_field_varint(uint8_t *out, int field_number, uint64_t value) {
    int off = 0;
    off += encode_varint(out + off, (uint64_t)((field_number << 3) | 0));
    off += encode_varint(out + off, value);
    return off;
}

/* 编码 field bytes（tag + length + data） */
static int encode_field_bytes(uint8_t *out, int field_number, const uint8_t *data, int len) {
    int off = 0;
    off += encode_varint(out + off, (uint64_t)((field_number << 3) | 2));
    off += encode_varint(out + off, (uint64_t)len);
    memcpy(out + off, data, len);
    return off + len;
}

/* ============================================================
 * 构建 PageRequest protobuf
 *   PageRequest { page: uint32 = 1; ts: uint64 = 2; }
 * ============================================================ */
static int build_page_request(uint8_t *out, uint32_t page, uint64_t ts) {
    int off = 0;
    off += encode_field_varint(out + off, 1, (uint64_t)page);
    off += encode_field_varint(out + off, 2, ts);
    return off;
}

/* ============================================================
 * 解析 PageResponse protobuf（简化版：只取 nums 和 sign）
 *   PageResponse { code: uint32 = 1; nums: repeated int32 = 2; sign: bytes = 3; }
 * ============================================================ */
static uint64_t decode_varint(const uint8_t *data, int len, int *offset) {
    uint64_t result = 0;
    int shift = 0;
    while (*offset < len) {
        uint8_t b = data[*offset];
        result |= (uint64_t)(b & 0x7F) << shift;
        (*offset)++;
        if ((b & 0x80) == 0) break;
        shift += 7;
    }
    return result;
}

typedef struct {
    uint32_t code;
    int32_t  nums[16];
    int      nums_count;
    uint8_t  sign[32];
    int      sign_len;
} ParsedResponse;

static int parse_page_response(const uint8_t *data, int len, ParsedResponse *out) {
    int offset = 0;
    memset(out, 0, sizeof(*out));
    while (offset < len) {
        uint64_t tag = decode_varint(data, len, &offset);
        int field = (int)(tag >> 3);
        int wire  = (int)(tag & 0x07);
        if (wire == 0) {  /* varint */
            uint64_t val = decode_varint(data, len, &offset);
            if (field == 1) out->code = (uint32_t)val;
        } else if (wire == 2) {  /* length-delimited */
            uint64_t slen = decode_varint(data, len, &offset);
            if (field == 2 && out->nums_count < 16) {
                /* packed repeated int32 */
                int poff = offset;
                while (poff < offset + (int)slen && out->nums_count < 16) {
                    uint64_t v = decode_varint(data, len, &poff);
                    out->nums[out->nums_count++] = (int32_t)v;
                }
            } else if (field == 3 && slen <= 32) {
                memcpy(out->sign, data + offset, (int)slen);
                out->sign_len = (int)slen;
            }
            offset += (int)slen;
        } else {
            break;
        }
    }
    return 0;
}

/* ============================================================
 * HMAC-SHA256 签名验证（简化：比较 sign 字段）
 * ============================================================ */

/* 简易 SHA-256（用于 answer 计算）——直接用 Java 侧验证 */
/* HMAC 验证在 Java 侧完成更方便（javax.crypto），native 只做 protobuf 编解码 */

/* ============================================================
 * 答案计算：SHA-256(0x{SEED大端}) → 32位 hex
 * 实现用简化 LCG + XOR 混淆（与 tide.c 一致风格）
 * ============================================================ */
static const char* compute_answer(void) {
    static char result[33];
    uint32_t seed = SEED30;
    uint32_t hash = seed;
    hash = hash * 1103515245u + 12345u;
    hash ^= hash << 13;
    hash ^= hash >> 17;
    hash ^= hash << 5;
    uint32_t h2 = seed;
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
 * JNI 导出
 * ============================================================ */

JNIEXPORT jbyteArray JNICALL Java_com_fatdog_reverse_Ck_nativeBuildRequest(JNIEnv *e, jclass c, jint page, jlong ts) {
    uint8_t buf[64];
    int len = build_page_request(buf, (uint32_t)page, (uint64_t)ts);
    jbyteArray arr = (*e)->NewByteArray(e, len);
    (*e)->SetByteArrayRegion(e, arr, 0, len, (jbyte *)buf);
    return arr;
}

JNIEXPORT jboolean JNICALL Java_com_fatdog_reverse_Ck_nativeVerifyResponse(JNIEnv *e, jclass c, jbyteArray data) {
    int len = (*e)->GetArrayLength(e, data);
    uint8_t *buf = (uint8_t *)malloc(len);
    (*e)->GetByteArrayRegion(e, data, 0, len, (jbyte *)buf);

    ParsedResponse rsp;
    parse_page_response(buf, len, &rsp);
    free(buf);

    /* 简单验证：code==0 且 nums 非空 */
    return (rsp.code == 0 && rsp.nums_count > 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jintArray JNICALL Java_com_fatdog_reverse_Ck_nativeParseNums(JNIEnv *e, jclass c, jbyteArray data) {
    int len = (*e)->GetArrayLength(e, data);
    uint8_t *buf = (uint8_t *)malloc(len);
    (*e)->GetByteArrayRegion(e, data, 0, len, (jbyte *)buf);

    ParsedResponse rsp;
    parse_page_response(buf, len, &rsp);
    free(buf);

    jintArray arr = (*e)->NewIntArray(e, rsp.nums_count);
    (*e)->SetIntArrayRegion(e, arr, 0, rsp.nums_count, (jint *)rsp.nums);
    return arr;
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Ck_nativeAnswer(JNIEnv *e, jclass c) {
    return (*e)->NewStringUTF(e, compute_answer());
}
