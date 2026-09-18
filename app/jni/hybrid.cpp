/**
 * hybrid.cpp — KL45 深渊合璧（须弥界 · 综合收官卷）
 *
 * 本关两道锁，收束前四关手段：
 *   第一层（JS 层，混淆在 assets/h5/hybrid_kl45.html 里）：AES-128-ECB 把 "page=..&ts=.." 加密成 enc，
 *                                                            钥 Fatdog_abyss 藏在被搅乱的 JS 里。
 *   第二层（本 so）：对 "Fatdog_abyss|page=..&ts=..&enc=.." 取一次普通 MD5 作为签名。
 *   两层钥不同、算法不同（分组密码 vs 摘要），都得还原。
 *
 * 反调试（评分制，防误报）：三路信号各记 1 分，>=2 才判定被调试；判定成立则改用诱饵钥签名 → 服务端 403。
 *   ① /proc/self/status 的 TracerPid 非 0
 *   ② ptrace(PTRACE_TRACEME) 失败
 *   ③ /proc/self/maps 出现 frida / gdb / lldb / gum-js 等调试器特征
 *
 * 宿主自测：g++ -DHYBRID_HOST_TEST 编译后打印签名并与 Python 对拍。
 */

#include <string>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <iomanip>
#include <cstdlib>

#ifndef HYBRID_HOST_TEST
  #include <jni.h>
  #include <android/log.h>
  #include <sys/ptrace.h>
  #define LOG_TAG "HYBRID"
  #define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#else
  #define LOGI(...) do { printf(__VA_ARGS__); printf("\n"); } while (0)
#endif

/* ==================== 钥匙（异或数组，运行时还原） ==================== */

/* 真标记 ^0x3C —— "Fatdog_abyss" */
static const volatile uint8_t KEY_TRUE[] = {
    122, 93, 72, 88, 83, 91, 99, 93, 94, 69, 79, 79
};

/* 诱饵钥 ^0x3C —— "Fatdog_deep" */
static const volatile uint8_t KEY_DECOY[] = {
    122, 93, 72, 88, 83, 91, 99, 88, 89, 89, 76
};

static std::string decodeKey(const volatile uint8_t* arr, size_t len) {
    std::string r;
    r.reserve(len);
    for (size_t i = 0; i < len; i++) r += (char)(arr[i] ^ 0x3C);
    return r;
}

/* ==================== MD5 ==================== */

static const uint32_t MD5_K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

static const uint8_t MD5_S[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void md5_transform(uint32_t st[4], const uint8_t blk[64]) {
    uint32_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] = (uint32_t)blk[i*4] | ((uint32_t)blk[i*4+1] << 8) |
               ((uint32_t)blk[i*4+2] << 16) | ((uint32_t)blk[i*4+3] << 24);
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
    for (int i = 0; i < 64; i++) {
        uint32_t f; int g;
        if (i < 16) { f = (b & c) | (~b & d);   g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5*i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d;        g = (3*i + 5) & 15; }
        else { f = c ^ (b | ~d);                 g = (7*i) & 15; }
        uint32_t tmp = d;
        d = c; c = b;
        b = b + rotl32(a + f + MD5_K[i] + M[g], MD5_S[i]);
        a = tmp;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
}

static void md5(const uint8_t* data, size_t len, uint8_t out[16]) {
    uint32_t st[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    size_t i = 0;
    for (; i + 64 <= len; i += 64) md5_transform(st, data + i);
    uint8_t buf[128];
    memset(buf, 0, 128);
    size_t rem = len - i;
    if (rem) memcpy(buf, data + i, rem);
    buf[rem] = 0x80;
    size_t padlen = (rem < 56) ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++) buf[padlen - 8 + j] = (bits >> (8 * j)) & 0xFF;
    md5_transform(st, buf);
    if (padlen == 128) md5_transform(st, buf + 64);
    for (int j = 0; j < 4; j++) {
        out[j*4]   = st[j] & 0xFF;
        out[j*4+1] = (st[j] >> 8) & 0xFF;
        out[j*4+2] = (st[j] >> 16) & 0xFF;
        out[j*4+3] = (st[j] >> 24) & 0xFF;
    }
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
#ifdef HYBRID_HOST_TEST
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

static const int GUARD_THRESHOLD = 2;

static bool guard_tripped() {
    static int cached = -1;
    if (cached < 0) cached = guard_score() >= GUARD_THRESHOLD ? 1 : 0;
    return cached == 1;
}

/* ==================== 业务 ==================== */

static std::string signPayload(const std::string& key, int page, long long ts, const std::string& enc) {
    std::string msg = key + "|page=" + std::to_string(page) + "&ts=" + std::to_string(ts) + "&enc=" + enc;
    uint8_t d[16];
    md5(reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), d);
    return toHex(d, 16);
}

/* ==================== 宿主自测 ==================== */
#ifdef HYBRID_HOST_TEST

int main() {
    std::string key = decodeKey(KEY_TRUE, sizeof(KEY_TRUE));
    std::string decoy = decodeKey(KEY_DECOY, sizeof(KEY_DECOY));
    printf("sign key  = %s\n", key.c_str());
    printf("decoy key = %s\n", decoy.c_str());
    printf("guard score = %d (threshold %d)\n", guard_score(), GUARD_THRESHOLD);
    uint8_t probe[16];
    md5(reinterpret_cast<const uint8_t*>("abc"), 3, probe);
    printf("md5(\"abc\") = %s\n", toHex(probe, 16).c_str());
    std::string enc = "fde4cf8e74b7234e9b74a8518d68f45104e418d80767db6e8276cdc6dc4a3c21";
    printf("sign(1,1787013761,enc) = %s\n", signPayload(key, 1, 1787013761LL, enc).c_str());
    printf("decoysign              = %s\n", signPayload(decoy, 1, 1787013761LL, enc).c_str());
    return 0;
}

#else

extern "C" {

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_HybridCore_nativeFullSign
        (JNIEnv* env, jclass, jint page, jlong ts, jstring enc) {
    const char* e = enc ? env->GetStringUTFChars(enc, nullptr) : "";
    std::string encStr = e ? e : "";
    if (enc) env->ReleaseStringUTFChars(enc, e);
    std::string key = guard_tripped()
            ? decodeKey(KEY_DECOY, sizeof(KEY_DECOY))
            : decodeKey(KEY_TRUE, sizeof(KEY_TRUE));
    return env->NewStringUTF(signPayload(key, page, (long long)ts, encStr).c_str());
}

JNIEXPORT jboolean JNICALL Java_com_fatdog_reverse_HybridCore_nativeVerify
        (JNIEnv* env, jclass, jint page, jlong ts, jstring enc, jstring sign) {
    const char* e = enc ? env->GetStringUTFChars(enc, nullptr) : "";
    std::string encStr = e ? e : "";
    if (enc) env->ReleaseStringUTFChars(enc, e);
    const char* s = sign ? env->GetStringUTFChars(sign, nullptr) : "";
    std::string signStr = s ? s : "";
    if (sign) env->ReleaseStringUTFChars(sign, s);
    std::string key = decodeKey(KEY_TRUE, sizeof(KEY_TRUE));
    bool ok = signPayload(key, page, (long long)ts, encStr) == signStr;
    return ok ? JNI_TRUE : JNI_FALSE;
}

/* 只读自检：只报告守卫命中了几个信号，不吐钥、不判胜 */
JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_HybridCore_nativeStatus
        (JNIEnv* env, jclass) {
    char buf[128];
    snprintf(buf, sizeof(buf), "%.1f/%d 信号命中（%s）",
             (double)guard_score(), GUARD_THRESHOLD + 1,
             guard_tripped() ? "判定被调试" : "安静");
    return env->NewStringUTF(buf);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;
    LOGI("hybrid loaded");
    return JNI_VERSION_1_6;
}

} /* extern "C" */
#endif
