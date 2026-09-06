/**
 * loom.c — 天机阁 KL30 天机织锦（Protobuf 二进制协议）
 *
 * 协议：Protobuf 编码请求（PageRequest）→ 服务端返回 Protobuf（PageResponse + HMAC）
 * 破解路线：抓包 hex → protoc --decode_raw → 重建 .proto → Python 复刻取数求和
 * SEED = 20280724
 * Flag: FLAG_18_KL30{heavenly_loom}
 */

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* ============================================================
 * 诱饵标记：Fatdog_weave（真，服务端 HMAC 密钥）/ Fatdog_knit（假）
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
 * 解析 PageResponse protobuf
 *   PageResponse { code: uint32 = 1; nums: repeated int32 = 2; sign: bytes = 3; }
 * nums 兼容服务端逐条 varint 编码，也兼容 packed 编码。
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
            if (field == 2 && out->nums_count < 16) {
                out->nums[out->nums_count++] = (int32_t)val;
            }
        } else if (wire == 2) {  /* length-delimited */
            uint64_t slen = decode_varint(data, len, &offset);
            if (field == 2 && out->nums_count < 16) {
                /* packed repeated int32 */
                int poff = offset;
                while (poff < offset + (int)slen && poff < len && out->nums_count < 16) {
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
 * JNI 导出
 * ============================================================ */

static ParsedResponse parse_java_bytes(JNIEnv *e, jbyteArray data) {
    int len = (*e)->GetArrayLength(e, data);
    uint8_t *buf = (uint8_t *)malloc(len);
    (*e)->GetByteArrayRegion(e, data, 0, len, (jbyte *)buf);

    ParsedResponse rsp;
    parse_page_response(buf, len, &rsp);
    free(buf);
    return rsp;
}

JNIEXPORT jbyteArray JNICALL Java_com_fatdog_reverse_Ck_nativeBuildRequest(JNIEnv *e, jclass c, jint page, jlong ts) {
    uint8_t buf[64];
    int len = build_page_request(buf, (uint32_t)page, (uint64_t)ts);
    jbyteArray arr = (*e)->NewByteArray(e, len);
    (*e)->SetByteArrayRegion(e, arr, 0, len, (jbyte *)buf);
    return arr;
}

JNIEXPORT jboolean JNICALL Java_com_fatdog_reverse_Ck_nativeVerifyResponse(JNIEnv *e, jclass c, jbyteArray data) {
    ParsedResponse rsp = parse_java_bytes(e, data);
    return (rsp.code == 0 && rsp.nums_count > 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL Java_com_fatdog_reverse_Ck_nativeCode(JNIEnv *e, jclass c, jbyteArray data) {
    ParsedResponse rsp = parse_java_bytes(e, data);
    return (jint)rsp.code;
}

JNIEXPORT jintArray JNICALL Java_com_fatdog_reverse_Ck_nativeParseNums(JNIEnv *e, jclass c, jbyteArray data) {
    ParsedResponse rsp = parse_java_bytes(e, data);
    jintArray arr = (*e)->NewIntArray(e, rsp.nums_count);
    (*e)->SetIntArrayRegion(e, arr, 0, rsp.nums_count, (jint *)rsp.nums);
    return arr;
}

JNIEXPORT jbyteArray JNICALL Java_com_fatdog_reverse_Ck_nativeSign(JNIEnv *e, jclass c, jbyteArray data) {
    ParsedResponse rsp = parse_java_bytes(e, data);
    if (rsp.sign_len <= 0) return NULL;
    jbyteArray arr = (*e)->NewByteArray(e, rsp.sign_len);
    (*e)->SetByteArrayRegion(e, arr, 0, rsp.sign_len, (jbyte *)rsp.sign);
    return arr;
}
