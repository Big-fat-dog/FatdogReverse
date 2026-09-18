/**
 * kl41.cpp — KL41 纸上谈兵（须弥界 · JS Bundle 基础）
 *
 * 考点：
 *   1. JS bundle 中密钥被拆分为字符串片段 + base64 编码
 *   2. metro 混淆后的字符串还原
 *   3. HMAC-SHA256 签名（C++ 实现，无 OpenSSL 依赖）
 *   4. ptrace 反调试（检测即投毒）
 *
 * 密钥体系：
 *   - 真密钥：运行时由异或拆分数组还原，用于 HMAC-SHA256 签名
 *   - 诱饵：另一组异或拆分数组，签名会被服务端 403（反调试投毒用）
 *
 * 答案：与服务端一致——random.Random(SEED) 生成 1000 个 randint(1,100) 求和后取 sha256 前 8 位
 */

#include <jni.h>
#include <string>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <array>
#include <vector>
#include <sstream>
#include <iomanip>
#include <mutex>

#include <unistd.h>
#include <sys/ptrace.h>

#define LOG_TAG "KL41"
#include <android/log.h>
#include "mt_rng.h"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// ==================== 密钥异或数组（运行时还原） ====================

// 密钥材料 A：异或 0x3C 拆分存储，运行时还原（用于正常签名）
static const volatile uint8_t K41_KEY[] = {
    70^0x3C, 97^0x3C, 116^0x3C, 100^0x3C, 111^0x3C, 103^0x3C,
    95^0x3C, 116^0x3C, 97^0x3C, 99^0x3C, 116^0x3C, 105^0x3C, 99^0x3C
};

// 密钥材料 B：异或 0x3C 拆分存储，运行时还原（诱饵，服务端拒签）
static const volatile uint8_t K41_DECOY[] = {
    70^0x3C, 97^0x3C, 116^0x3C, 100^0x3C, 111^0x3C, 103^0x3C,
    95^0x3C, 112^0x3C, 108^0x3C, 97^0x3C, 110^0x3C
};

static std::string decodeXor(const volatile uint8_t* arr, size_t len) {
    std::string r;
    r.reserve(len);
    for (size_t i = 0; i < len; i++)
        r += (char)(arr[i] ^ 0x3C);
    return r;
}

// ==================== SHA-256（纯 C++ 实现） ====================

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    for (int i = 0; i < 16; i++)
        W[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
                ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(W[i-15], 7) ^ rotr(W[i-15], 18) ^ (W[i-15] >> 3);
        uint32_t s1 = rotr(W[i-2], 17) ^ rotr(W[i-2], 19) ^ (W[i-2] >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K256[i] + W[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint8_t buf[64];
    size_t total = len;
    // 完整块
    for (size_t i = 0; i + 64 <= len; i += 64)
        sha256_transform(state, data + i);
    // 填充
    size_t rem = len % 64;
    memset(buf, 0, 64);
    if (rem > 0) memcpy(buf, data + len - rem, rem);
    buf[rem] = 0x80;
    if (rem >= 56) {
        sha256_transform(state, buf);
        memset(buf, 0, 64);
    }
    uint64_t bits = total * 8;
    buf[56] = (bits >> 56) & 0xFF; buf[57] = (bits >> 48) & 0xFF;
    buf[58] = (bits >> 40) & 0xFF; buf[59] = (bits >> 32) & 0xFF;
    buf[60] = (bits >> 24) & 0xFF; buf[61] = (bits >> 16) & 0xFF;
    buf[62] = (bits >> 8) & 0xFF;  buf[63] = bits & 0xFF;
    sha256_transform(state, buf);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (state[i] >> 24) & 0xFF;
        out[i*4+1] = (state[i] >> 16) & 0xFF;
        out[i*4+2] = (state[i] >> 8) & 0xFF;
        out[i*4+3] = state[i] & 0xFF;
    }
}

// ==================== HMAC-SHA256 ====================

static void hmac_sha256(const uint8_t* key, size_t klen,
                        const uint8_t* data, size_t dlen,
                        uint8_t out[32]) {
    uint8_t k_buf[64];
    memset(k_buf, 0, 64);
    if (klen > 64) {
        sha256(key, klen, k_buf);
    } else {
        memcpy(k_buf, key, klen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k_buf[i] ^ 0x36;
        opad[i] = k_buf[i] ^ 0x5C;
    }
    // inner: SHA256(ipad || data)
    uint8_t inner[64 + 1024];  // data 最多 ~1KB
    memcpy(inner, ipad, 64);
    if (dlen > 0 && dlen <= sizeof(inner) - 64)
        memcpy(inner + 64, data, dlen);
    sha256(inner, 64 + dlen, out);
    // outer: SHA256(opad || inner_hash)
    uint8_t outer[64 + 32];
    memcpy(outer, opad, 64);
    memcpy(outer + 64, out, 32);
    sha256(outer, 64 + 32, out);
}

// ==================== hex 编码 ====================

static std::string toHex(const uint8_t* data, size_t len) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++)
        ss << std::setw(2) << (int)data[i];
    return ss.str();
}

// ==================== 反调试 ====================

static bool detectDebugger() {
    // ptrace 检测
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) return true;
    // TracerPid 检测
    FILE* f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int pid = atoi(line + 10);
                fclose(f);
                if (pid != 0) return true;
                break;
            }
        }
        fclose(f);
    }
    return false;
}

// ==================== JNI 接口 ====================

static jstring nativeSign(JNIEnv* env, jclass, jint page, jlong ts) {
    std::string key = decodeXor(K41_KEY, sizeof(K41_KEY));
    std::string msg = "page=" + std::to_string(page) + "&ts=" + std::to_string(ts);

    // 反调试：检测到调试器则用诱饵密钥
    if (detectDebugger()) {
        LOGW("debugger detected, using decoy key");
        key = decodeXor(K41_DECOY, sizeof(K41_DECOY));
    }

    uint8_t digest[32];
    hmac_sha256(reinterpret_cast<const uint8_t*>(key.data()), key.size(),
                reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                digest);
    std::string hex = toHex(digest, 32);
    return env->NewStringUTF(hex.c_str());
}

static jstring nativeDecoySign(JNIEnv* env, jclass, jint page, jlong ts) {
    std::string key = decodeXor(K41_DECOY, sizeof(K41_DECOY));
    std::string msg = "page=" + std::to_string(page) + "&ts=" + std::to_string(ts);
    uint8_t digest[32];
    hmac_sha256(reinterpret_cast<const uint8_t*>(key.data()), key.size(),
                reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                digest);
    std::string hex = toHex(digest, 32);
    return env->NewStringUTF(hex.c_str());
}

static jboolean nativeVerify(JNIEnv* env, jclass, jint page, jlong ts, jstring sign) {
    std::string key = decodeXor(K41_KEY, sizeof(K41_KEY));
    std::string msg = "page=" + std::to_string(page) + "&ts=" + std::to_string(ts);
    uint8_t digest[32];
    hmac_sha256(reinterpret_cast<const uint8_t*>(key.data()), key.size(),
                reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                digest);
    std::string expected = toHex(digest, 32);
    const char* signStr = env->GetStringUTFChars(sign, nullptr);
    bool ok = (expected == signStr);
    env->ReleaseStringUTFChars(sign, signStr);
    return ok ? JNI_TRUE : JNI_FALSE;
}

static jstring nativeAnswer(JNIEnv* env, jclass) {
    // 与服务端 server.py 完全一致：random.Random(20280801) 生成 1000 个 randint(1,100)
    // 求和后再 sha256(str(sum))[:8]。此处从同一 SEED 现场复算，避免硬编码错位。
    uint64_t sum = mt_rng::kl_server_sum(20280801);
    std::string sumStr = std::to_string(sum);
    uint8_t digest[32];
    sha256(reinterpret_cast<const uint8_t*>(sumStr.data()), sumStr.size(), digest);
    std::string hex = toHex(digest, 32).substr(0, 8);
    return env->NewStringUTF(hex.c_str());
}

static jboolean nativeDetectDebug(JNIEnv*, jclass) {
    return detectDebugger() ? JNI_TRUE : JNI_FALSE;
}

// ==================== JNI_OnLoad（动态注册） ====================

static const JNINativeMethod gMethods[] = {
    {"nativeSign",      "(IJ)Ljava/lang/String;",  (void*)nativeSign},
    {"nativeDecoySign", "(IJ)Ljava/lang/String;",  (void*)nativeDecoySign},
    {"nativeVerify",    "(IJLjava/lang/String;)Z", (void*)nativeVerify},
    {"nativeAnswer",    "()Ljava/lang/String;",    (void*)nativeAnswer},
    {"nativeDetectDebug","()Z",                    (void*)nativeDetectDebug},
};

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;
    jclass cls = env->FindClass("com/fatdog/reverse/RnBridge");
    if (!cls) return JNI_ERR;
    if (env->RegisterNatives(cls, gMethods, sizeof(gMethods)/sizeof(gMethods[0])) < 0)
        return JNI_ERR;
    LOGI("KL41 loaded, methods registered");
    return JNI_VERSION_1_6;
}
