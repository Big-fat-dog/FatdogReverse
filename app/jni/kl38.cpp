/**
 * kl38.cpp — KL38 雾里观花（碧落天 · Flutter 网络层 Hook）
 *
 * 考点：
 *   1. Flutter 自定义 HttpClient 请求构建（非 Java OkHttp）
 *   2. Dart 层 SSL Pinning（证书 SHA-256 校验）
 *   3. Dart Isolate 内签名计算 + FFI 边界
 *   4. 反调试检测 + 静默投毒
 *
 * 密钥体系：
 *   - 真密钥：Fatdog_haze（HMAC-SHA256 签名）
 *   - 诱饵：Fatdog_fog（签名会被服务端 403）
 *   - SSL Pin：硬编码证书 SHA-256 哈希
 *
 * 反逆向：
 *   - ptrace/TracerPid 检测
 *   - /proc/self/maps 扫描 Frida 特征
 *   - 27042-27044 端口探测
 *   - 线程名扫描（gum-js-loop 等）
 *   - 检测命中即投毒密钥一字节，服务端 403
 *
 * 答案：SHA256("20280701") 前 8 位 hex
 * 标记：Fatdog_haze（真）/ Fatdog_fog（诱饵）
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

#define LOG_TAG "KL38"
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
        for (int i = 0; i < N - 1; i++) r[i] = data[i] ^ 0x3C;
        return r;
    }
};

// ==================== 密钥异或数组（运行时还原） ====================

// Fatdog_haze = {70,97,116,100,111,103,95,104,97,122,101} XOR 0x3C
static const volatile uint8_t K38_KEY_PART[] = {
    70^0x3C, 97^0x3C, 116^0x3C, 100^0x3C, 111^0x3C, 103^0x3C,
    95^0x3C, 104^0x3C, 97^0x3C, 122^0x3C, 101^0x3C
};

// Fatdog_fog = {70,97,116,100,111,103,95,102,111,103} XOR 0x3C
static const volatile uint8_t K38_DECOY[] = {
    70^0x3C, 97^0x3C, 116^0x3C, 100^0x3C, 111^0x3C, 103^0x3C,
    95^0x3C, 102^0x3C, 111^0x3C, 103^0x3C
};

// SSL Pin 哈希（模拟证书 SHA-256）
static const volatile uint8_t K38_PIN[] = {
    0xa3, 0xf1, 0x2b, 0x4c, 0x8d, 0xe5, 0x70, 0x9a,
    0x3c, 0xb6, 0x14, 0x5e, 0x82, 0xd9, 0x6f, 0x01,
    0x47, 0xa8, 0xc3, 0x5d, 0x9e, 0x2b, 0xf4, 0x76,
    0x18, 0xac, 0x53, 0xd0, 0x87, 0xe2, 0x41, 0x69
};

static std::string decodeKey() {
    std::string r;
    r.reserve(sizeof(K38_KEY_PART));
    for (size_t i = 0; i < sizeof(K38_KEY_PART); i++)
        r += (char)(K38_KEY_PART[i] ^ 0x3C);
    return r;
}

static std::string decodeDecoy() {
    std::string r;
    r.reserve(sizeof(K38_DECOY));
    for (size_t i = 0; i < sizeof(K38_DECOY); i++)
        r += (char)(K38_DECOY[i] ^ 0x3C);
    return r;
}

static std::string decodePin() {
    std::string r;
    r.reserve(sizeof(K38_PIN) * 2);
    for (size_t i = 0; i < sizeof(K38_PIN); i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", K38_PIN[i]);
        r += buf;
    }
    return r;
}

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
            // 非阻塞连接检测
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

// ==================== 签名计算 ====================

static std::string compute_sign(int page, long ts, bool use_real_key) {
    if (g_key_poisoned) return "guard_failed";
    std::string key = use_real_key ? decodeKey() : decodeDecoy();
    char buf[128];
    snprintf(buf, sizeof(buf), "page=%d&ts=%ld", page, ts);
    return hmacSha256Hex(key, std::string(buf));
}

// ==================== 请求构建（模拟 Flutter HttpClient） ====================

static std::string build_request(int page, long ts) {
    std::string sign = compute_sign(page, ts, true);
    char url[256];
    snprintf(url, sizeof(url),
        "GET /api/kl38?page=%d&ts=%ld&sign=%s HTTP/1.1\r\n"
        "Host: 127.0.0.1:8443\r\n"
        "User-Agent: Flutter/3.x\r\n"
        "Accept: application/json\r\n"
        "X-Flutter-Engine: Dart/3.x\r\n"
        "Connection: close\r\n"
        "\r\n",
        page, ts, sign.c_str());
    return std::string(url);
}

// ==================== JNI 函数 ====================

static JNIEnv* g_env = nullptr;
static jobject g_thiz = nullptr;

extern "C" {

// 静态注册：nativeBuildRequest
JNIEXPORT jbyteArray JNICALL
Java_com_fatdog_reverse_FlutterNet_nativeBuildRequest(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    if (!guard_check()) {
        jbyteArray arr = env->NewByteArray(0);
        return arr;
    }
    std::string req = build_request(page, (long)ts);
    jbyteArray arr = env->NewByteArray(req.size());
    env->SetByteArrayRegion(arr, 0, req.size(), (const jbyte*)req.data());
    return arr;
}

// 静态注册：nativeGetPinHash
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterNet_nativeGetPinHash(JNIEnv *env, jclass clazz) {
    std::string pin = decodePin();
    return env->NewStringUTF(pin.c_str());
}

// 动态注册函数

static jstring nativeSign(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    if (!guard_check()) {
        return env->NewStringUTF("guard_failed");
    }
    std::string sign = compute_sign(page, (long)ts, true);
    return env->NewStringUTF(sign.c_str());
}

static jboolean nativeVerify(JNIEnv *env, jclass clazz, jint page, jlong ts, jstring signStr) {
    if (!guard_check()) return JNI_FALSE;
    const char* signC = env->GetStringUTFChars(signStr, nullptr);
    std::string provided(signC);
    env->ReleaseStringUTFChars(signStr, signC);

    // 尝试真密钥
    std::string expected = compute_sign(page, (long)ts, true);
    if (provided == expected) return JNI_TRUE;

    // 尝试诱饵密钥 → 服务端会 403
    std::string decoy_expected = compute_sign(page, (long)ts, false);
    if (provided == decoy_expected) return JNI_FALSE;

    return JNI_FALSE;
}

static jstring nativeAnswer(JNIEnv *env, jclass clazz) {
    // SHA256(str(sum))[:8]，sum 由 SEED_KL38=20280701 现场复算
    std::string ans = sha256Hex(std::to_string(mt_rng::kl_server_sum(20280701)));
    return env->NewStringUTF(ans.substr(0, 8).c_str());
}

static jstring nativeGetStatus(JNIEnv *env, jclass clazz) {
    std::ostringstream ss;
    ss << "=== KL38 哨兵状态 ===\n";
    ss << "反调试: " << (g_key_poisoned ? "已投毒" : "正常") << "\n";

    int bits = anti_debug::run_all();
    ss << "ptrace: " << ((bits & 3) ? "触发" : "安全") << "\n";
    ss << "maps: " << ((bits & 4) ? "触发" : "安全") << "\n";
    ss << "port: " << ((bits & 8) ? "触发" : "安全") << "\n";
    ss << "threads: " << ((bits & 16) ? "触发" : "安全") << "\n";
    ss << "SSL Pin: " << decodePin().substr(0, 16) << "...\n";
    return env->NewStringUTF(ss.str().c_str());
}

// ==================== JNI_OnLoad 动态注册 ====================

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;

    jclass cls = env->FindClass("com/fatdog/reverse/FlutterNet");
    if (!cls) return JNI_ERR;

    JNINativeMethod methods[] = {
        {(char*)"nativeSign",    (char*)"(IJ)Ljava/lang/String;", (void*)nativeSign},
        {(char*)"nativeVerify",  (char*)"(IJLjava/lang/String;)Z", (void*)nativeVerify},
        {(char*)"nativeAnswer",  (char*)"()Ljava/lang/String;",   (void*)nativeAnswer},
        {(char*)"nativeGetStatus",(char*)"()Ljava/lang/String;",  (void*)nativeGetStatus},
    };
    env->RegisterNatives(cls, methods, 4);
    return JNI_VERSION_1_6;
}

} // extern "C"
