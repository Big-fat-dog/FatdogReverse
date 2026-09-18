/**
 * signbridge.cpp — KL44 暗流涌动（须弥界 · JSBridge 签名拦截 + JS 层加密）
 *
 * 双层：
 *   第一层（JS 层，混淆在 assets/h5/sign_kl44.html 里）：RC4 把 "page=..&ts=.." 加密成 enc，钥 Fatdog_pearl。
 *   第二层（本 so）：对 "page=..&ts=..&enc=.." 做 HMAC-SHA256，钥 Fatdog_surge。
 *   两层钥不同、算法不同，都得还原。
 *
 * 反调试（评分制，避免误报）：三路信号各记 1 分，>=2 才判定被调试；判定成立则改用诱饵钥签名 → 服务端 403。
 *   ① /proc/self/status 的 TracerPid 非 0
 *   ② ptrace(PTRACE_TRACEME) 失败
 *   ③ /proc/self/maps 出现 frida / gdb / lldb / gum-js 等调试器特征
 *
 * 宿主自测：g++ -DSIGNBRIDGE_HOST_TEST 编译后打印签名并与 Python 对拍。
 */

#include <string>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <iomanip>
#include <cstdlib>

#ifndef SIGNBRIDGE_HOST_TEST
  #include <jni.h>
  #include <android/log.h>
  #include <sys/ptrace.h>
  #define LOG_TAG "SIGNBRIDGE"
  #define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#else
  #define LOGI(...) do { printf(__VA_ARGS__); printf("\n"); } while (0)
#endif

/* ==================== 钥匙（异或数组，运行时还原） ==================== */

/* native 签名钥 ^0x3C —— "Fatdog_surge" */
static const volatile uint8_t KEY_SIGN[] = {
    122, 93, 72, 88, 83, 91, 99, 79, 73, 78, 91, 89
};

/* 诱饵钥 ^0x3C —— "Fatdog_foam" */
static const volatile uint8_t KEY_DECOY[] = {
    122, 93, 72, 88, 83, 91, 99, 90, 83, 93, 81
};

static std::string decodeKey(const volatile uint8_t* arr, size_t len) {
    std::string r;
    r.reserve(len);
    for (size_t i = 0; i < len; i++) r += (char)(arr[i] ^ 0x3C);
    return r;
}

/* ==================== SHA-256 / HMAC-SHA256 ==================== */

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
    for (size_t i = 0; i + 64 <= len; i += 64) sha256_transform(state, data + i);
    size_t rem = len % 64;
    memset(buf, 0, 64);
    if (rem > 0) memcpy(buf, data + len - rem, rem);
    buf[rem] = 0x80;
    if (rem >= 56) { sha256_transform(state, buf); memset(buf, 0, 64); }
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
    for (int i = 0; i < 64; i++) { ipad[i] = k_buf[i] ^ 0x36; opad[i] = k_buf[i] ^ 0x5C; }
    uint8_t inner[64 + 512];
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

/* ==================== 反调试（评分制，防误报） ==================== */

static int sig_tracerpid() {
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    int pid = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) { pid = atoi(line + 10); break; }
    }
    fclose(f);
    return pid != 0 ? 1 : 0;
}

static int sig_ptrace() {
#ifdef SIGNBRIDGE_HOST_TEST
    return 0;
#else
    return ptrace(PTRACE_TRACEME, 0, 0, 0) == -1 ? 1 : 0;
#endif
}

static int sig_maps() {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    int hit = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "frida") || strstr(line, "gdb") ||
            strstr(line, "lldb") || strstr(line, "gum-js")) { hit = 1; break; }
    }
    fclose(f);
    return hit;
}

static int guard_score() { return sig_tracerpid() + sig_ptrace() + sig_maps(); }

static const size_t GUARD_THRESHOLD = 2;

static bool guard_tripped() {
    static int cached = -1;
    if (cached < 0) cached = guard_score() >= (int)GUARD_THRESHOLD ? 1 : 0;
    return cached == 1;
}

/* ==================== 业务 ==================== */

static std::string signPayload(const std::string& key, int page, long long ts, const std::string& enc) {
    std::string msg = "page=" + std::to_string(page) + "&ts=" + std::to_string(ts) + "&enc=" + enc;
    uint8_t d[32];
    hmac_sha256(reinterpret_cast<const uint8_t*>(key.data()), key.size(),
                reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), d);
    return toHex(d, 32);
}

/* ==================== 宿主自测 ==================== */
#ifdef SIGNBRIDGE_HOST_TEST

int main() {
    std::string key = decodeKey(KEY_SIGN, sizeof(KEY_SIGN));
    std::string decoy = decodeKey(KEY_DECOY, sizeof(KEY_DECOY));
    printf("sign key  = %s\n", key.c_str());
    printf("decoy key = %s\n", decoy.c_str());
    printf("guard score = %d (threshold %zu)\n", guard_score(), GUARD_THRESHOLD);
    std::string enc = "10505b4d47fd3c00d52415a5b364f140791b705b";
    printf("sign(1,1787013761,enc) = %s\n", signPayload(key, 1, 1787013761LL, enc).c_str());
    printf("decoysign              = %s\n", signPayload(decoy, 1, 1787013761LL, enc).c_str());
    return 0;
}

#else

extern "C" {

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_SignBridge_nativeBridgeSign
        (JNIEnv* env, jclass, jint page, jlong ts, jstring enc) {
    const char* e = enc ? env->GetStringUTFChars(enc, nullptr) : "";
    std::string encStr = e ? e : "";
    if (enc) env->ReleaseStringUTFChars(enc, e);
    std::string key = guard_tripped()
            ? decodeKey(KEY_DECOY, sizeof(KEY_DECOY))
            : decodeKey(KEY_SIGN, sizeof(KEY_SIGN));
    return env->NewStringUTF(signPayload(key, page, (long long)ts, encStr).c_str());
}

JNIEXPORT jboolean JNICALL Java_com_fatdog_reverse_SignBridge_nativeVerify
        (JNIEnv* env, jclass, jint page, jlong ts, jstring enc, jstring sign) {
    const char* e = enc ? env->GetStringUTFChars(enc, nullptr) : "";
    std::string encStr = e ? e : "";
    if (enc) env->ReleaseStringUTFChars(enc, e);
    const char* s = sign ? env->GetStringUTFChars(sign, nullptr) : "";
    std::string signStr = s ? s : "";
    if (sign) env->ReleaseStringUTFChars(sign, s);
    std::string key = decodeKey(KEY_SIGN, sizeof(KEY_SIGN));
    bool ok = signPayload(key, page, (long long)ts, encStr) == signStr;
    return ok ? JNI_TRUE : JNI_FALSE;
}

/* 只读自检：只报告守卫命中了几个信号，不吐钥、不判胜 */
JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_SignBridge_nativeStatus
        (JNIEnv* env, jclass) {
    char buf[128];
    snprintf(buf, sizeof(buf), "%.1f/%d 信号命中（%s）",
             (double)guard_score(), (int)GUARD_THRESHOLD + 1,
             guard_tripped() ? "判定被调试" : "安静");
    return env->NewStringUTF(buf);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;
    LOGI("signbridge loaded");
    return JNI_VERSION_1_6;
}

} /* extern "C" */
#endif
