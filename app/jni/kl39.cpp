/**
 * kl39.cpp — KL39 月下独酌（碧落天 · Dart FFI 双向往调）
 *
 * 考点：
 *   1. Dart FFI 双向往调：Dart 调 C 加密，C 回调 Dart 取密钥材料
 *   2. 密钥分片：Dart 持有 FRAG_DART（前 16 字节），C 持有 FRAG_C（后 16 字节）
 *   3. 运行时合并：两片拼接为 32 字节 HMAC 密钥
 *   4. 反调试检测 + 静默投毒（与 kl38 同源四检）
 *
 * 密钥体系：
 *   - 真密钥：Fatdog_moon（HMAC-SHA256 签名）
 *   - 诱饵：Fatdog_star（签名会被服务端 403）
 *   - 分片密钥：FRAG_DART(16B) + FRAG_C(16B) = 32B full_key
 *   - 解码异或：^0x42（区分 kl38 的 ^0x3C）
 *
 * 反逆向：
 *   - ptrace/TracerPid 检测
 *   - /proc/self/maps 扫描 Frida 特征
 *   - 27042-27044 端口探测
 *   - 线程名扫描（gum-js-loop 等）
 *   - 检测命中即投毒密钥一字节，服务端 403
 *
 * 答案：SHA256(str(sum)) 前 8 位 hex（sum=49978）
 * 标记：Fatdog_moon（真）/ Fatdog_star（诱饵）
 */

#include <jni.h>
#include "mt_rng.h"
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <dirent.h>

#define LOG_TAG "KL39"
#include <android/log.h>
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// ==================== 编译期 XOR 字符串 ====================

template<int N>
struct XorStr {
    char data[N];
    constexpr XorStr(const char (&s)[N], char key) : data{} {
        for (int i = 0; i < N; i++) data[i] = s[i] ^ key;
    }
    std::string get() const {
        std::string r(N - 1, '\0');
        for (int i = 0; i < N - 1; i++) r[i] = data[i] ^ 0x42;
        return r;
    }
};

// ==================== 密钥异或数组（运行时还原） ====================
// 分片设计：FRAG_DART + FRAG_C = 32 字节完整密钥
// Dart 持有前 16 字节，C 持有后 16 字节，运行时合并

// FRAG_DART: 解码后 = {70,97,116,100,111,103,95,109,111,111,110,0xAB,0xCD,0xEF,0x12,0x34}
// 前 11 字节 = "Fatdog_moon"，后 5 字节 = Dart 侧填充
static const volatile uint8_t K39_FRAG_DART[] = {
    70^0x42, 97^0x42, 116^0x42, 100^0x42, 111^0x42, 103^0x42,
    95^0x42, 109^0x42, 111^0x42, 111^0x42, 110^0x42,
    0xAB^0x42, 0xCD^0x42, 0xEF^0x42, 0x12^0x42, 0x34^0x42
};

// FRAG_C: 解码后 = {0x56,0x78,0x9A,0xBC,0xDE,0xF0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA}
// C 侧持有的后半段密钥分片
static const volatile uint8_t K39_FRAG_C[] = {
    0x56^0x42, 0x78^0x42, 0x9A^0x42, 0xBC^0x42, 0xDE^0x42, 0xF0^0x42,
    0x11^0x42, 0x22^0x42, 0x33^0x42, 0x44^0x42, 0x55^0x42, 0x66^0x42,
    0x77^0x42, 0x88^0x42, 0x99^0x42, 0xAA^0x42
};

// Fatdog_star = {70,97,116,100,111,103,95,115,116,97,114} XOR 0x42（诱饵密钥）
static const volatile uint8_t K39_DECOY[] = {
    70^0x42, 97^0x42, 116^0x42, 100^0x42, 111^0x42, 103^0x42,
    95^0x42, 115^0x42, 116^0x42, 97^0x42, 114^0x42
};

// Fatdog_moon = {70,97,116,100,111,103,95,109,111,111,110} XOR 0x42（真密钥，直接用于 HMAC）
static const volatile uint8_t K39_KEY[] = {
    70^0x42, 97^0x42, 116^0x42, 100^0x42, 111^0x42, 103^0x42,
    95^0x42, 109^0x42, 111^0x42, 111^0x42, 110^0x42
};

// XOR 编码密钥（用于 encRequest 加密运算）
static const volatile uint8_t K39_ROLL_KEY[] = {
    0x42, 0x97, 0x13, 0x58, 0xA1, 0x2B, 0x6F, 0xC3
};

static std::string decodeFragDart() {
    std::string r;
    r.reserve(sizeof(K39_FRAG_DART));
    for (size_t i = 0; i < sizeof(K39_FRAG_DART); i++)
        r += (char)(K39_FRAG_DART[i] ^ 0x42);
    return r;
}

static std::string decodeFragC() {
    std::string r;
    r.reserve(sizeof(K39_FRAG_C));
    for (size_t i = 0; i < sizeof(K39_FRAG_C); i++)
        r += (char)(K39_FRAG_C[i] ^ 0x42);
    return r;
}

static std::string decodeDecoy() {
    std::string r;
    r.reserve(sizeof(K39_DECOY));
    for (size_t i = 0; i < sizeof(K39_DECOY); i++)
        r += (char)(K39_DECOY[i] ^ 0x42);
    return r;
}

static std::string decodeKey() {
    std::string r;
    r.reserve(sizeof(K39_KEY));
    for (size_t i = 0; i < sizeof(K39_KEY); i++)
        r += (char)(K39_KEY[i] ^ 0x42);
    return r;
}

// 合并分片：FRAG_DART + FRAG_C = 32 字节完整密钥
static std::string assembleFullKey() {
    std::string dart = decodeFragDart();
    std::string cfrag = decodeFragC();
    return dart + cfrag;
}

// ==================== FFI 注册表模拟 ====================
// 模拟 Dart FFI native function 注册表，IDA 分析时增加迷惑性

struct FfiFunc { const char* name; void* ptr; };

// 前向声明静态注册函数，作为 FFI 注册表指针
static jstring nativeSign_enc(JNIEnv *env, jclass cls, jint page, jlong ts);
static jstring nativeDeriveKey_enc(JNIEnv *env, jclass cls);
static jbyteArray nativeEncRequest_enc(JNIEnv *env, jclass cls, jint page, jlong ts);

static const FfiFunc FFI_REGISTRY[] = {
    {"encRequest",   (void*)nativeEncRequest_enc},
    {"deriveKey",    (void*)nativeDeriveKey_enc},
    {"signData",     (void*)nativeSign_enc},
    // 诱饵条目，增加 IDA 分析复杂度
    {"verifyPin",    (void*)0x12345},
    {"initIsolate",  (void*)0x6789A},
    {"getTimestamp", (void*)0xABCD},
};

static const int FFI_REGISTRY_SIZE = sizeof(FFI_REGISTRY) / sizeof(FFI_REGISTRY[0]);

// ==================== SHA-256 实现 ====================

namespace sha256_detail {
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    inline uint32_t Ch(uint32_t e, uint32_t f, uint32_t g) { return (e & f) ^ (~e & g); }
    inline uint32_t Maj(uint32_t a, uint32_t b, uint32_t c) { return (a & b) ^ (a & c) ^ (b & c); }
    inline uint32_t Sigma0(uint32_t a) { return rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22); }
    inline uint32_t Sigma1(uint32_t e) { return rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25); }

    struct Ctx {
        uint32_t h[8];
        uint64_t bitlen;
        uint8_t data[64];
        size_t datalen;
        Ctx() { h[0]=0x6a09e667; h[1]=0xbb67ae85; h[2]=0x3c6ef372; h[3]=0xa54ff53a;
                h[4]=0x510e527f; h[5]=0x9b05688c; h[6]=0x1f83d9ab; h[7]=0x5be0cd19;
                bitlen=0; datalen=0; }
    };

    static void transform(Ctx& c, const uint8_t data[64]) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)data[i*4]<<24)|((uint32_t)data[i*4+1]<<16)|((uint32_t)data[i*4+2]<<8)|data[i*4+3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
            uint32_t s1 = rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
            w[i] = w[i-16]+s0+w[i-7]+s1;
        }
        uint32_t a=c.h[0],b=c.h[1],cc=c.h[2],d=c.h[3],e=c.h[4],f=c.h[5],g=c.h[6],h=c.h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
            uint32_t ch=Ch(e,f,g);
            uint32_t temp1=h+S1+ch+K[i]+w[i];
            uint32_t S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
            uint32_t mj=Maj(a,b,cc);
            uint32_t temp2=S0+mj;
            h=g; g=f; f=e; e=d+temp1; d=cc; cc=b; b=a; a=temp1+temp2;
        }
        c.h[0]+=a; c.h[1]+=b; c.h[2]+=cc; c.h[3]+=d;
        c.h[4]+=e; c.h[5]+=f; c.h[6]+=g; c.h[7]+=h;
    }

    static void update(Ctx& c, const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; i++) {
            c.data[c.datalen++] = data[i];
            if (c.datalen == 64) { transform(c, c.data); c.bitlen += 512; c.datalen = 0; }
        }
    }

    static std::string final(Ctx& c) {
        uint64_t bits = c.bitlen + c.datalen * 8;
        c.data[c.datalen++] = 0x80;
        if (c.datalen > 56) { while (c.datalen < 64) c.data[c.datalen++] = 0; transform(c, c.data); c.datalen = 0; }
        while (c.datalen < 56) c.data[c.datalen++] = 0;
        for (int i = 7; i >= 0; i--) c.data[c.datalen++] = (bits >> (i*8)) & 0xff;
        transform(c, c.data);
        char out[65];
        for (int i = 0; i < 8; i++)
            snprintf(out + i*8, 9, "%08x", c.h[i]);
        return std::string(out, 64);
    }

    static std::string hash(const uint8_t* data, size_t len) {
        Ctx c;
        update(c, data, len);
        return final(c);
    }
}

static std::string sha256Hex(const std::string& s) {
    return sha256_detail::hash((const uint8_t*)s.data(), s.size());
}

// ==================== HMAC-SHA256 ====================

static std::string hmacSha256Hex(const std::string& key, const std::string& msg) {
    std::string k = key;
    if (k.size() > 64) k = sha256Hex(k);
    while (k.size() < 64) k += '\0';
    std::string ipad(64, 0x36), opad(64, 0x5c);
    for (int i = 0; i < 64; i++) { ipad[i] ^= k[i]; opad[i] ^= k[i]; }
    std::string inner = sha256_detail::hash((const uint8_t*)(ipad + msg).data(), ipad.size() + msg.size());
    std::string outer = sha256_detail::hash((const uint8_t*)(opad + inner).data(), opad.size() + inner.size());
    return outer;
}

// ==================== 反调试检测 ====================

namespace anti_debug {
    // 检测 1: ptrace + TracerPid
    static int check_ptrace() {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) return 1;
        FILE* f = fopen("/proc/self/status", "r");
        if (!f) return 0;
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int pid = atoi(line + 10);
                fclose(f);
                if (pid != 0) return 2;
                return 0;
            }
        }
        fclose(f);
        return 0;
    }

    // 检测 2: /proc/self/maps Frida 特征
    static int check_maps() {
        FILE* f = fopen("/proc/self/maps", "r");
        if (!f) return 0;
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "frida") || strstr(line, "gadget") ||
                strstr(line, "gum-js") || strstr(line, "linjector") ||
                strstr(line, "re.frida.server")) {
                fclose(f);
                return 4;
            }
        }
        fclose(f);
        return 0;
    }

    // 检测 3: 27042-27044 端口
    static int check_port() {
        for (int port = 27042; port <= 27044; port++) {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) continue;
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
            struct timeval tv = {0, 300000}; // 300ms
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            int ret = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
            close(fd);
            if (ret == 0) return 8;
        }
        return 0;
    }

    // 检测 4: 线程名扫描
    static int check_threads() {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/task", getpid());
        DIR* d = opendir(path);
        if (!d) return 0;
        struct dirent* de;
        while ((de = readdir(d)) != nullptr) {
            if (de->d_name[0] == '.') continue;
            char comm_path[128];
            snprintf(comm_path, sizeof(comm_path), "/proc/%d/task/%s/comm", getpid(), de->d_name);
            FILE* f = fopen(comm_path, "r");
            if (!f) continue;
            char name[64];
            if (fgets(name, sizeof(name), f)) {
                name[strcspn(name, "\n")] = 0;
                if (strstr(name, "gum-js") || strstr(name, "gmain") ||
                    strstr(name, "gdbus") || strstr(name, "pool-frida") ||
                    strstr(name, "frida")) {
                    fclose(f);
                    closedir(d);
                    return 16;
                }
            }
            fclose(f);
        }
        closedir(d);
        return 0;
    }

    static int run_all() {
        return check_ptrace() | check_maps() | check_port() | check_threads();
    }
}

// ==================== 投毒机制 ====================

static bool g_key_poisoned = false;

static void poison_key() {
    if (!g_key_poisoned) {
        g_key_poisoned = true;
        LOGW("Key poisoned due to anti-debug detection");
    }
}

static bool guard_check() {
    int bits = anti_debug::run_all();
    if (bits != 0) {
        poison_key();
        return false;
    }
    return true;
}

// ==================== 分片密钥操作 ====================
// 模拟 Dart FFI 双向往调的密钥组装流程

// 模拟 Dart 侧持有 FRAG_DART（JIT 编译后存储于 Dart 堆）
static std::string g_dart_fragment;
static bool g_dart_fragment_loaded = false;

// 模拟 C 侧持有 FRAG_C（编译进 native library）
static std::string c_fragment;

// 初始化 C 侧分片（库加载时执行）
static void initFragments() {
    c_fragment = decodeFragC();
    LOGI("C-side fragment initialized (%zu bytes)", c_fragment.size());
}

// 模拟 Dart 回调获取 FRAG_DART（C 调 Dart）
static std::string ffiCallbackGetDartFragment() {
    if (!g_dart_fragment_loaded) {
        g_dart_fragment = decodeFragDart();
        g_dart_fragment_loaded = true;
        LOGI("Dart fragment retrieved via FFI callback (%zu bytes)", g_dart_fragment.size());
    }
    return g_dart_fragment;
}

// 模拟 Dart 回调获取完整密钥（C 调 Dart，再组合）
static std::string ffiCallbackAssembleKey() {
    std::string dart_frag = ffiCallbackGetDartFragment();
    // 拼接：Dart 分片 + C 分片 = 32 字节
    std::string full = dart_frag + c_fragment;
    LOGI("Full key assembled: %zu bytes", full.size());
    return full;
}

// ==================== 加密运算（模拟 FFI 调用链） ====================

// 模拟 Dart 调 C 进行 XOR 加密，C 内部回调 Dart 获取密钥材料
static std::string ffiEncryptPayload(int page, long ts) {
    if (g_key_poisoned) return "";

    // Step 1: C 回调 Dart 获取密钥分片
    std::string full_key = ffiCallbackAssembleKey();

    // Step 2: 构建明文
    char plaintext[128];
    int len = snprintf(plaintext, sizeof(plaintext), "page=%d&ts=%ld", page, ts);

    // Step 3: XOR 加密（使用合并密钥 + 滚动密钥混合）
    std::string encrypted;
    encrypted.reserve(len);
    const uint8_t* roll = const_cast<const uint8_t*>(K39_ROLL_KEY);
    for (int i = 0; i < len; i++) {
        uint8_t k_byte = (uint8_t)full_key[i % full_key.size()];
        uint8_t r_byte = roll[i % sizeof(K39_ROLL_KEY)];
        encrypted += (char)(plaintext[i] ^ k_byte ^ r_byte);
    }
    return encrypted;
}

// 模拟 C 调 Dart 获取密钥后进行 HMAC 签名
static std::string ffiComputeSign(int page, long ts, bool use_real_key) {
    if (g_key_poisoned) return "guard_failed";
    std::string key;
    if (use_real_key) {
        // 直接使用真密钥（模拟 Dart FFI 回调获取的完整密钥）
        key = decodeKey();
    } else {
        key = decodeDecoy();
    }
    char buf[128];
    snprintf(buf, sizeof(buf), "page=%d&ts=%ld", page, ts);
    return hmacSha256Hex(key, std::string(buf));
}

// ==================== JNI 函数 ====================

static jstring nativeSign_enc(JNIEnv *env, jclass cls, jint page, jlong ts) {
    // 声明为 JNI 签名：(IJ)Ljava/lang/String;
    (void)env; (void)cls; (void)page; (void)ts;
    return nullptr; // 占位，实际通过 JNI_OnLoad 注册
}

static jstring nativeDeriveKey_enc(JNIEnv *env, jclass cls) {
    (void)env; (void)cls;
    return nullptr; // 占位
}

static jbyteArray nativeEncRequest_enc(JNIEnv *env, jclass cls, jint page, jlong ts) {
    (void)env; (void)cls; (void)page; (void)ts;
    return nullptr; // 占位
}

extern "C" {

// 1. nativeEncRequest(int page, long ts) -> byte[]
//    模拟 FFI 链加密：Dart 调 C 加密，C 回调 Dart 取密钥材料
static jbyteArray nativeEncRequest(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    if (!guard_check()) {
        jbyteArray arr = env->NewByteArray(0);
        return arr;
    }
    std::string encrypted = ffiEncryptPayload(page, (long)ts);
    jbyteArray arr = env->NewByteArray(encrypted.size());
    env->SetByteArrayRegion(arr, 0, encrypted.size(), (const jbyte*)encrypted.data());
    return arr;
}

// 2. nativeDeriveKey() -> String
//    模拟 C 回调 Dart 获取完整组装密钥的 hex 字符串
static jstring nativeDeriveKey(JNIEnv *env, jclass clazz) {
    if (!guard_check()) {
        return env->NewStringUTF("guard_failed");
    }
    std::string full_key = ffiCallbackAssembleKey();
    // 将密钥转为 hex 字符串显示
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c : full_key) {
        ss << std::setw(2) << (int)c;
    }
    return env->NewStringUTF(ss.str().c_str());
}

// 3. nativeSign(int page, long ts) -> String
//    反调试检查 + HMAC-SHA256(完整密钥, "page=N&ts=T")
static jstring nativeSign(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    if (!guard_check()) {
        return env->NewStringUTF("guard_failed");
    }
    std::string sign = ffiComputeSign(page, (long)ts, true);
    return env->NewStringUTF(sign.c_str());
}

// 4. nativeVerify(int page, long ts, String sign) -> boolean
//    反调试检查 + 真密钥验证，尝试诱饵密钥
static jboolean nativeVerify(JNIEnv *env, jclass clazz, jint page, jlong ts, jstring signStr) {
    if (!guard_check()) return JNI_FALSE;
    const char* signC = env->GetStringUTFChars(signStr, nullptr);
    std::string provided(signC);
    env->ReleaseStringUTFChars(signStr, signC);

    // 尝试真密钥
    std::string expected = ffiComputeSign(page, (long)ts, true);
    if (provided == expected) return JNI_TRUE;

    // 尝试诱饵密钥 → 服务端会 403
    std::string decoy_expected = ffiComputeSign(page, (long)ts, false);
    if (provided == decoy_expected) return JNI_FALSE;

    return JNI_FALSE;
}

// 5. nativeAnswer() -> String
//    SHA256(str(sum)) 前 8 位 hex，sum 由 SEED_KL39=20280715 现场复算
static jstring nativeAnswer(JNIEnv *env, jclass clazz) {
    std::string ans = sha256Hex(std::to_string(mt_rng::kl_server_sum(20280715)));
    return env->NewStringUTF(ans.substr(0, 8).c_str());
}

// 6. nativeGetStatus() -> String
//    反调试状态、密钥组装状态、FFI 注册表信息
static jstring nativeGetStatus(JNIEnv *env, jclass clazz) {
    std::ostringstream ss;
    ss << "=== KL39 月下独酌 FFI 状态 ===\n";

    // 反调试状态
    ss << "反调试: " << (g_key_poisoned ? "已投毒" : "正常") << "\n";
    int bits = anti_debug::run_all();
    ss << "ptrace: " << ((bits & 3) ? "触发" : "安全") << "\n";
    ss << "maps: " << ((bits & 4) ? "触发" : "安全") << "\n";
    ss << "port: " << ((bits & 8) ? "触发" : "安全") << "\n";
    ss << "threads: " << ((bits & 16) ? "触发" : "安全") << "\n";

    // 密钥分片状态
    ss << "--- 密钥分片 ---\n";
    ss << "FRAG_DART: " << decodeFragDart().size() << " bytes"
       << " (loaded: " << (g_dart_fragment_loaded ? "yes" : "no") << ")\n";
    ss << "FRAG_C: " << decodeFragC().size() << " bytes\n";
    ss << "Full key: " << assembleFullKey().size() << " bytes (assembled)\n";

    // FFI 注册表
    ss << "--- FFI Registry ---\n";
    for (int i = 0; i < FFI_REGISTRY_SIZE; i++) {
        ss << "  [" << i << "] " << FFI_REGISTRY[i].name
           << " -> 0x" << std::hex << (uintptr_t)FFI_REGISTRY[i].ptr << std::dec << "\n";
    }

    return env->NewStringUTF(ss.str().c_str());
}

// ==================== JNI_OnLoad 动态注册 ====================

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;

    jclass cls = env->FindClass("com/fatdog/reverse/FlutterFFI");
    if (!cls) return JNI_ERR;

    // 初始化 C 侧密钥分片
    initFragments();

    JNINativeMethod methods[] = {
        {(char*)"nativeEncRequest",  (char*)"(IJ)[B",                    (void*)nativeEncRequest},
        {(char*)"nativeDeriveKey",   (char*)"()Ljava/lang/String;",     (void*)nativeDeriveKey},
        {(char*)"nativeSign",        (char*)"(IJ)Ljava/lang/String;",   (void*)nativeSign},
        {(char*)"nativeVerify",      (char*)"(IJLjava/lang/String;)Z",  (void*)nativeVerify},
        {(char*)"nativeAnswer",      (char*)"()Ljava/lang/String;",     (void*)nativeAnswer},
        {(char*)"nativeGetStatus",   (char*)"()Ljava/lang/String;",     (void*)nativeGetStatus},
    };
    env->RegisterNatives(cls, methods, 6);

    LOGI("KL39 loaded: FlutterFFI registered (%d methods, %d FFI entries)",
         6, FFI_REGISTRY_SIZE);
    return JNI_VERSION_1_6;
}

} // extern "C"
