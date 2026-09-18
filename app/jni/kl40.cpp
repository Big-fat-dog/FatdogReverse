/**
 * kl40.cpp — KL40 星河倒影（碧落天 · 综合收官卷）
 *
 * 考点：
 *   1. 多层安全架构：AOT 加密 + FFI + Dart Isolate 签名 + 反调试
 *   2. 密钥派生体系：HMAC 密钥 / RC4 密钥 / AOT 密钥 从主密钥派生
 *   3. RC4 响应加密 + HMAC 请求签名
 *   4. 证书固定（Cert Pinning）+ 代码完整性校验
 *   5. 四重反调试检测 + 静默投毒
 *
 * 密钥体系：
 *   - 主密钥：Fatdog_reflect（UTF-8: 70,97,116,100,111,103,95,114,101,102,108,101,99,116）
 *   - 诱饵：Fatdog_echo
 *   - HMAC 密钥 = 主密钥（裸密钥，不经 SHA256 派生；与 server.py hmac.new(KEY_KL40, msg) 一致）
 *   - RC4 密钥 = SHA256("Fatdog_reflect|rc4")[:16]
 *   - AOT 密钥 = SHA256("Fatdog_reflect|aot")[:16]
 *   - 解码异或：^0x55（区分 kl38 的 ^0x3C、kl39 的 ^0x42）
 *
 * 反逆向：
 *   - ptrace/TracerPid 检测
 *   - /proc/self/maps 扫描 Frida 特征
 *   - 27042-27044 端口探测
 *   - 线程名扫描（gum-js-loop 等）
 *   - 检测命中即投毒密钥一字节，服务端 403
 *
 * 答案：SHA256(str(sum)) 前 8 位 hex（sum=52005）
 * 标记：Fatdog_reflect（真）/ Fatdog_echo（诱饵）
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

#define LOG_TAG "KL40"
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
        for (int i = 0; i < N - 1; i++) r[i] = data[i] ^ 0x55;
        return r;
    }
};

// ==================== 密钥异或数组（运行时还原） ====================

// Fatdog_reflect = {70,97,116,100,111,103,95,114,101,102,108,101,99,116} XOR 0x55
static const volatile uint8_t K40_KEY_PART[] = {
    70^0x55, 97^0x55, 116^0x55, 100^0x55, 111^0x55, 103^0x55,
    95^0x55, 114^0x55, 101^0x55, 102^0x55, 108^0x55, 101^0x55,
    99^0x55, 116^0x55
};

// Fatdog_echo = {70,97,116,100,111,103,95,101,99,104,111} XOR 0x55
static const volatile uint8_t K40_DECOY[] = {
    70^0x55, 97^0x55, 116^0x55, 100^0x55, 111^0x55, 103^0x55,
    95^0x55, 101^0x55, 99^0x55, 104^0x55, 111^0x55
};

// Fatdog_reflect 直接密钥（用于 HMAC，与服务端一致）
static const volatile uint8_t K40_RAW_KEY[] = {
    70^0x55, 97^0x55, 116^0x55, 100^0x55, 111^0x55, 103^0x55,
    95^0x55, 114^0x55, 101^0x55, 102^0x55, 108^0x55, 101^0x55,
    99^0x55, 116^0x55
};

// Cert Pin 哈希（模拟证书 SHA-256）
static const volatile uint8_t K40_PIN[] = {
    0xb7, 0x2e, 0x4a, 0x1f, 0x9d, 0xc3, 0x65, 0x88,
    0x41, 0xa9, 0xd0, 0x73, 0x26, 0x5b, 0xe8, 0x1c,
    0x8f, 0x34, 0xa2, 0x67, 0xd1, 0x49, 0x5c, 0xb0,
    0x23, 0xf6, 0x78, 0x1a, 0xc5, 0x3d, 0x94, 0xe7
};

static std::string decodeKey() {
    std::string r;
    r.reserve(sizeof(K40_KEY_PART));
    for (size_t i = 0; i < sizeof(K40_KEY_PART); i++)
        r += (char)(K40_KEY_PART[i] ^ 0x55);
    return r;
}

static std::string decodeDecoy() {
    std::string r;
    r.reserve(sizeof(K40_DECOY));
    for (size_t i = 0; i < sizeof(K40_DECOY); i++)
        r += (char)(K40_DECOY[i] ^ 0x55);
    return r;
}

static std::string decodeRawKey() {
    std::string r;
    r.reserve(sizeof(K40_RAW_KEY));
    for (size_t i = 0; i < sizeof(K40_RAW_KEY); i++)
        r += (char)(K40_RAW_KEY[i] ^ 0x55);
    return r;
}

static std::string decodePin() {
    std::string r;
    r.reserve(sizeof(K40_PIN) * 2);
    for (size_t i = 0; i < sizeof(K40_PIN); i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", K40_PIN[i]);
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

// ==================== RC4 实现 ====================

namespace rc4_detail {
    struct RC4State {
        uint8_t S[256];
        int i, j;
    };

    // Key Scheduling Algorithm (KSA)
    static void ksa(RC4State& state, const uint8_t* key, size_t keylen) {
        for (int i = 0; i < 256; i++)
            state.S[i] = (uint8_t)i;
        uint8_t j = 0;
        for (int i = 0; i < 256; i++) {
            j = j + state.S[i] + key[i % keylen];
            uint8_t tmp = state.S[i];
            state.S[i] = state.S[j];
            state.S[j] = tmp;
        }
        state.i = 0;
        state.j = 0;
    }

    // Pseudo-Random Generation Algorithm (PRGA)
    static uint8_t prga(RC4State& state) {
        state.i = (state.i + 1) & 0xFF;
        state.j = (state.j + state.S[state.i]) & 0xFF;
        uint8_t tmp = state.S[state.i];
        state.S[state.i] = state.S[state.j];
        state.S[state.j] = tmp;
        return state.S[(state.S[state.i] + state.S[state.j]) & 0xFF];
    }

    // RC4 加密/解密（对称）
    static std::string crypt(const uint8_t* key, size_t keylen,
                             const uint8_t* data, size_t datalen) {
        RC4State state;
        ksa(state, key, keylen);
        std::string result(datalen, '\0');
        for (size_t i = 0; i < datalen; i++) {
            uint8_t keystream = prga(state);
            result[i] = (char)(data[i] ^ keystream);
        }
        return result;
    }
}

// ==================== 密钥派生 ====================

static std::string g_hmac_key;
static std::string g_rc4_key;
static std::string g_aot_key;
static bool g_keys_derived = false;

static void deriveKeys() {
    if (g_keys_derived) return;
    std::string master = decodeRawKey();

    // HMAC key = 直接使用主密钥（与服务端 hmac.new(key, msg) 一致）
    g_hmac_key = master;

    // RC4 key = SHA256(master + "|rc4").digest()[:16]（二进制，非 hex 文本）
    std::string rc4_input = master + "|rc4";
    std::string rc4_full = sha256Hex(rc4_input);
    // 服务端用 .digest()[:16]（二进制），这里从 hex 还原为二进制字节
    g_rc4_key.reserve(16);
    for (size_t i = 0; i < 16 && i * 2 + 1 < rc4_full.size(); i++) {
        char byte_str[3] = {rc4_full[i*2], rc4_full[i*2+1], '\0'};
        g_rc4_key += (char)(uint8_t)strtol(byte_str, nullptr, 16);
    }

    // AOT key = SHA256(master + "|aot").digest()[:16]（同理）
    std::string aot_input = master + "|aot";
    std::string aot_full = sha256Hex(aot_input);
    g_aot_key.reserve(16);
    for (size_t i = 0; i < 16 && i * 2 + 1 < aot_full.size(); i++) {
        char byte_str[3] = {aot_full[i*2], aot_full[i*2+1], '\0'};
        g_aot_key += (char)(uint8_t)strtol(byte_str, nullptr, 16);
    }

    g_keys_derived = true;
    LOGI("Keys derived: hmac=%zu rc4=%zu aot=%zu",
         g_hmac_key.size(), g_rc4_key.size(), g_aot_key.size());
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

// ==================== 代码完整性校验 ====================

// 模拟对关键代码段进行哈希校验（检测二进制篡改）
static bool g_integrity_ok = true;

static void verifyCodeIntegrity() {
    // 取关键函数指针附近的字节计算哈希
    // 实际中会校验 .text 段关键区域
    extern char __attribute__((weak)) _etext;
    extern char __attribute__((weak)) _text_start;

    // 简单校验：检查几个关键函数指针不为零
    if ((void*)anti_debug::run_all == nullptr ||
        (void*)rc4_detail::crypt == nullptr ||
        (void*)hmacSha256Hex == nullptr) {
        g_integrity_ok = false;
        LOGW("Code integrity check failed!");
        return;
    }

    // 模拟计算代码段哈希并与预期值比较
    // 这里用函数指针地址的低 16 位作为简单校验
    uintptr_t ptr1 = (uintptr_t)&anti_debug::run_all;
    uintptr_t ptr2 = (uintptr_t)&rc4_detail::crypt;
    uintptr_t ptr3 = (uintptr_t)&hmacSha256Hex;

    // 组合指针值生成校验哈希
    char buf[64];
    snprintf(buf, sizeof(buf), "%lx:%lx:%lx", ptr1, ptr2, ptr3);
    std::string hash = sha256Hex(std::string(buf));

    // 检查哈希是否合理（实际会与硬编码值比较）
    if (hash.empty() || hash.size() < 16) {
        g_integrity_ok = false;
        LOGW("Integrity hash generation failed!");
    } else {
        g_integrity_ok = true;
        LOGI("Code integrity verified: %s", hash.substr(0, 16).c_str());
    }
}

// ==================== 签名计算 ====================

static std::string compute_sign(int page, long ts, bool use_real_key) {
    if (g_key_poisoned) return "guard_failed";
    deriveKeys();

    std::string hmac_key;
    if (use_real_key) {
        hmac_key = g_hmac_key;
    } else {
        // 诱饵密钥直接使用（与服务端 hmac.new(decoy, msg) 一致）
        hmac_key = decodeDecoy();
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "page=%d&ts=%ld", page, ts);
    return hmacSha256Hex(hmac_key, std::string(buf));
}

// ==================== RC4 响应解密 ====================

static std::string decrypt_response(const std::string& hex_data) {
    if (g_key_poisoned) return "";
    deriveKeys();

    // 将 hex 转为字节
    std::vector<uint8_t> encrypted;
    encrypted.reserve(hex_data.size() / 2);
    for (size_t i = 0; i + 1 < hex_data.size(); i += 2) {
        char byte_str[3] = {hex_data[i], hex_data[i+1], '\0'};
        encrypted.push_back((uint8_t)strtol(byte_str, nullptr, 16));
    }

    // RC4 解密
    return rc4_detail::crypt(
        (const uint8_t*)g_rc4_key.data(), g_rc4_key.size(),
        encrypted.data(), encrypted.size());
}

// ==================== AOT 加密模拟 ====================

// 模拟 Dart AOT 编译后的代码段加密
// 实际中用于保护 Dart 编译产物不被逆向
static std::string aotEncrypt(const std::string& data) {
    if (g_key_poisoned) return "";
    deriveKeys();

    // 使用 AOT 密钥进行简单 XOR 加密（实际会用更复杂的算法）
    std::string result;
    result.reserve(data.size());
    for (size_t i = 0; i < data.size(); i++) {
        result += (char)(data[i] ^ g_aot_key[i % g_aot_key.size()]);
    }
    return result;
}

// ==================== 时间戳验证 ====================

static bool validateTimestamp(long ts) {
    // 检查时间戳是否在合理范围内（防止重放攻击）
    long now = (long)time(nullptr);
    long diff = now - ts;
    if (diff < 0) diff = -diff;
    // 允许 5 分钟的时间偏差
    return diff <= 300;
}

// ==================== JNI 函数 ====================

extern "C" {

// 1. nativeFullSign(int page, long ts) -> String
//    反调试检查 + HMAC-SHA256(hmac_key, "page=N&ts=T")
static jstring nativeFullSign(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    if (!guard_check()) {
        return env->NewStringUTF("guard_failed");
    }

    // 时间戳验证
    if (!validateTimestamp((long)ts)) {
        LOGW("Timestamp validation failed: ts=%ld", (long)ts);
        return env->NewStringUTF("timestamp_invalid");
    }

    std::string sign = compute_sign(page, (long)ts, true);
    return env->NewStringUTF(sign.c_str());
}

// 2. nativeDecryptRsp(String hex_data) -> String
//    反调试检查 + RC4 解密
static jstring nativeDecryptRsp(JNIEnv *env, jclass clazz, jstring hex_data) {
    if (!guard_check()) {
        return env->NewStringUTF("guard_failed");
    }

    if (hex_data == nullptr) {
        return env->NewStringUTF("");
    }

    const char* hexC = env->GetStringUTFChars(hex_data, nullptr);
    std::string hexStr(hexC);
    env->ReleaseStringUTFChars(hex_data, hexC);

    std::string decrypted = decrypt_response(hexStr);
    return env->NewStringUTF(decrypted.c_str());
}

// 3. nativeVerifyIntegrity() -> boolean
//    代码完整性校验
static jboolean nativeVerifyIntegrity(JNIEnv *env, jclass clazz) {
    verifyCodeIntegrity();
    return g_integrity_ok ? JNI_TRUE : JNI_FALSE;
}

// 4. nativeAnswer() -> String
//    SHA256(str(sum)) 前 8 位 hex，sum 由 SEED_KL40=20280720 现场复算
static jstring nativeAnswer(JNIEnv *env, jclass clazz) {
    std::string ans = sha256Hex(std::to_string(mt_rng::kl_server_sum(20280720)));
    return env->NewStringUTF(ans.substr(0, 8).c_str());
}

// 5. nativeGetStatus() -> String
//    反调试状态、完整性状态、密钥信息
static jstring nativeGetStatus(JNIEnv *env, jclass clazz) {
    std::ostringstream ss;
    ss << "=== KL40 星河倒影 综合收官状态 ===\n";

    // 反调试状态
    ss << "反调试: " << (g_key_poisoned ? "已投毒" : "正常") << "\n";
    int bits = anti_debug::run_all();
    ss << "ptrace: " << ((bits & 3) ? "触发" : "安全") << "\n";
    ss << "maps: " << ((bits & 4) ? "触发" : "安全") << "\n";
    ss << "port: " << ((bits & 8) ? "触发" : "安全") << "\n";
    ss << "threads: " << ((bits & 16) ? "触发" : "安全") << "\n";

    // 完整性状态
    ss << "--- 完整性 ---\n";
    ss << "代码校验: " << (g_integrity_ok ? "通过" : "失败") << "\n";

    // 密钥信息
    ss << "--- 密钥体系 ---\n";
    deriveKeys();
    ss << "主密钥: " << decodeKey() << "\n";
    ss << "HMAC 密钥: " << g_hmac_key.substr(0, 16) << "...\n";
    ss << "RC4 密钥: ";
    for (size_t i = 0; i < g_rc4_key.size(); i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", (uint8_t)g_rc4_key[i]);
        ss << buf;
    }
    ss << "\n";
    ss << "AOT 密钥: ";
    for (size_t i = 0; i < g_aot_key.size(); i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", (uint8_t)g_aot_key[i]);
        ss << buf;
    }
    ss << "\n";
    ss << "Cert Pin: " << decodePin().substr(0, 16) << "...\n";
    ss << "XOR key: 0x55\n";

    // 安全层总结
    ss << "--- 安全层 ---\n";
    ss << "AOT 加密: 已启用\n";
    ss << "FFI 签名: 已启用\n";
    ss << "Dart Isolate: 已启用\n";
    ss << "反调试: 4 重检测\n";
    ss << "证书固定: 已启用\n";
    ss << "HMAC 签名: 已启用\n";
    ss << "RC4 加密: 已启用\n";

    return env->NewStringUTF(ss.str().c_str());
}

// ==================== JNI_OnLoad 动态注册 ====================

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;

    jclass cls = env->FindClass("com/fatdog/reverse/FlutterMirror");
    if (!cls) return JNI_ERR;

    // 初始化密钥派生
    deriveKeys();

    // 代码完整性校验
    verifyCodeIntegrity();

    JNINativeMethod methods[] = {
        {(char*)"nativeFullSign",         (char*)"(IJ)Ljava/lang/String;",   (void*)nativeFullSign},
        {(char*)"nativeDecryptRsp",       (char*)"(Ljava/lang/String;)Ljava/lang/String;", (void*)nativeDecryptRsp},
        {(char*)"nativeVerifyIntegrity",  (char*)"()Z",                      (void*)nativeVerifyIntegrity},
        {(char*)"nativeAnswer",           (char*)"()Ljava/lang/String;",     (void*)nativeAnswer},
        {(char*)"nativeGetStatus",        (char*)"()Ljava/lang/String;",     (void*)nativeGetStatus},
    };
    env->RegisterNatives(cls, methods, 5);

    LOGI("KL40 loaded: FlutterMirror registered (%d methods, integrity=%s)",
         5, g_integrity_ok ? "ok" : "FAIL");
    return JNI_VERSION_1_6;
}

} // extern "C"
