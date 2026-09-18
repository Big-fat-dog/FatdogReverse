/**
 * h5shell.cpp — KL41 浅滩拾贝（须弥界 · H5 壳 / JSBridge 注入定位）
 *
 * 考点：
 *   1. WebView 加载本地 H5，Java 侧 addJavascriptInterface 注入 bridge 对象
 *   2. bridge 的 @JavascriptInterface 方法名需要在 jadx 里定位（getToken/sign/verify/version）
 *   3. 真正的签名密钥不在 Java/DEX —— 藏在 libh5shell.so 的异或数组里，运行时才拼出
 *   4. HMAC-SHA256 签名（C++ 实现，无 OpenSSL 依赖）
 *
 * 密钥体系：
 *   - 真密钥：运行时由异或数组还原，用于 HMAC-SHA256 签名
 *   - 诱饵：另一组异或数组，签名会被服务端 403（诱饵类 ShellKit 亦持同名明文诱饵）
 *
 * 与宿主自测：g++ -DH5SHELL_HOST_TEST 编译后打印 sign/token，Python 侧逐字节对拍。
 */

#include <string>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <iomanip>

#ifdef H5SHELL_HOST_TEST
  #define LOGI(...) do { printf(__VA_ARGS__); printf("\n"); } while (0)
  #define LOGW(...) do { printf(__VA_ARGS__); printf("\n"); } while (0)
#else
  #include <jni.h>
  #include <android/log.h>
  #define LOG_TAG "H5SHELL"
  #define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
  #define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#endif

/* ==================== 密钥异或数组（运行时还原，volatile 防常量折叠） ==================== */

/* 真钥 ^0x3C —— "Fatdog_surf" */
static const volatile uint8_t KEY_REAL[] = {
    122, 93, 72, 88, 83, 91, 99, 79, 73, 78, 90
};

/* 诱饵 ^0x3C —— "Fatdog_drift"（一字之差，服务端拒签） */
static const volatile uint8_t KEY_DECOY[] = {
    122, 93, 72, 88, 83, 91, 99, 88, 78, 85, 90, 72
};

static std::string decodeKey(const volatile uint8_t* arr, size_t len) {
    std::string r;
    r.reserve(len);
    for (size_t i = 0; i < len; i++) r += (char)(arr[i] ^ 0x3C);
    return r;
}

/* ==================== SHA-256（纯 C++ 实现） ==================== */

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

static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    for (int i = 0; i < 16; i++)
        W[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
                ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(W[i-15], 7) ^ rotr32(W[i-15], 18) ^ (W[i-15] >> 3);
        uint32_t s1 = rotr32(W[i-2], 17) ^ rotr32(W[i-2], 19) ^ (W[i-2] >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K256[i] + W[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
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
    for (size_t i = 0; i + 64 <= len; i += 64)
        sha256_transform(state, data + i);
    size_t rem = len % 64;
    memset(buf, 0, 64);
    if (rem > 0) memcpy(buf, data + len - rem, rem);
    buf[rem] = 0x80;
    if (rem >= 56) {
        sha256_transform(state, buf);
        memset(buf, 0, 64);
    }
    uint64_t bits = (uint64_t)total * 8;
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

static void hmac_sha256(const uint8_t* key, size_t klen,
                        const uint8_t* data, size_t dlen, uint8_t out[32]) {
    uint8_t k_buf[64];
    memset(k_buf, 0, 64);
    if (klen > 64) sha256(key, klen, k_buf);
    else memcpy(k_buf, key, klen);
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k_buf[i] ^ 0x36;
        opad[i] = k_buf[i] ^ 0x5C;
    }
    uint8_t inner[64 + 256];
    memcpy(inner, ipad, 64);
    if (dlen > 0 && dlen <= sizeof(inner) - 64) memcpy(inner + 64, data, dlen);
    sha256(inner, 64 + dlen, out);
    uint8_t outer[64 + 32];
    memcpy(outer, opad, 64);
    memcpy(outer + 64, out, 32);
    sha256(outer, 64 + 32, out);
}

static std::string toHex(const uint8_t* data, size_t len) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) ss << std::setw(2) << (int)data[i];
    return ss.str();
}

/* ==================== 业务实现 ==================== */

/* bridge 方法表：供 Java 侧 bridgeInfo() 回显，也可由 jadx 从 @JavascriptInterface 直接读到 */
static const char* kBridgeMethods = "getToken|sign|verify|version";

static std::string hmacSign(const std::string& key, int page, long long ts) {
    std::string msg = "page=" + std::to_string(page) + "&ts=" + std::to_string(ts);
    uint8_t digest[32];
    hmac_sha256(reinterpret_cast<const uint8_t*>(key.data()), key.size(),
                reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), digest);
    return toHex(digest, 32);
}

/* token = sha256(真钥)[:8]，只吐派生值、不吐密钥明文 */
static std::string keyToken(const std::string& key) {
    uint8_t d[32];
    sha256(reinterpret_cast<const uint8_t*>(key.data()), key.size(), d);
    return toHex(d, 32).substr(0, 8);
}

/* ==================== 宿主自测（不参与真机构建） ==================== */
#ifdef H5SHELL_HOST_TEST

int main() {
    std::string real = decodeKey(KEY_REAL, sizeof(KEY_REAL));
    std::string decoy = decodeKey(KEY_DECOY, sizeof(KEY_DECOY));
    printf("real  = %s\n", real.c_str());
    printf("decoy = %s\n", decoy.c_str());
    printf("token = %s\n", keyToken(real).c_str());
    printf("sign(1,1787013761) = %s\n", hmacSign(real, 1, 1787013761LL).c_str());
    printf("decoysign          = %s\n", hmacSign(decoy, 1, 1787013761LL).c_str());
    printf("bridges = %s\n", kBridgeMethods);
    return 0;
}

#else

/* ==================== JNI 导出 ==================== */
extern "C" {

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_H5Shell_nativeSign
        (JNIEnv* env, jclass, jint page, jlong ts) {
    std::string key = decodeKey(KEY_REAL, sizeof(KEY_REAL));
    return env->NewStringUTF(hmacSign(key, page, (long long)ts).c_str());
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_H5Shell_nativeDecoySign
        (JNIEnv* env, jclass, jint page, jlong ts) {
    std::string key = decodeKey(KEY_DECOY, sizeof(KEY_DECOY));
    return env->NewStringUTF(hmacSign(key, page, (long long)ts).c_str());
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_H5Shell_nativeGetBridgeMethods
        (JNIEnv* env, jclass) {
    return env->NewStringUTF(kBridgeMethods);
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_H5Shell_nativeToken
        (JNIEnv* env, jclass) {
    std::string key = decodeKey(KEY_REAL, sizeof(KEY_REAL));
    return env->NewStringUTF(keyToken(key).c_str());
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;
    LOGI("h5shell loaded");
    return JNI_VERSION_1_6;
}

} /* extern "C" */
#endif
