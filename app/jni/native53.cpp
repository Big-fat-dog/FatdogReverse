/**
 * native53.cpp — L53 焚天火域（主入口 + 调度 + 异常控制流 · 最终关）
 *
 * 3 SO 分离：native53（调度+异常） + native53c（加密核心+密钥） + native53b（业务干扰）
 * 异常控制流：try/catch 里藏真逻辑
 * vtable 分发：CipherFactory 根据 algo_id 选择加密器
 * 深层调用栈（5+ 层）：JNI → k53_dispatch → ErrorHandler::process → CipherFactory::create → encryptor->encrypt
 * 协议：POST /api/l53 表单 page/ts/enc/aes/sign，响应 {"d": RC4 加密}
 * flag：FLAG_18_L53{scorched_fireland}
 */

#include <jni.h>
#include <string>
#include <cstring>
#include <cstdint>
#include <dlfcn.h>
#include <stdexcept>
#include <android/log.h>
#include <vector>

#define LOG_TAG "native53"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// ==================== dlopen 函数指针类型 ====================
typedef const uint8_t* (*get_key_func)();
typedef int (*feistel_core_fn)(const uint8_t*, int, uint8_t*, int, int*);
typedef int (*rc4_core_fn)(const uint8_t*, int, uint8_t*, int, int*);

// ==================== 异常控制流：ErrorHandler ====================
class ErrorHandler {
public:
    // 真逻辑藏在 catch 块里——IDA 看 try 块是空的，必须跟到 catch
    std::string process(const std::string& input) {
        try {
            // try 块：看似无意义的运算，实际是触发异常的引子
            volatile int trigger = 0;
            if (input.size() > 0) {
                // 正常路径：不会触发异常
                throw std::runtime_error("flow_control");
            }
            return "";
        } catch (const std::runtime_error& e) {
            // 真逻辑在这里：对 input 做变换
            std::string result = input;
            for (size_t i = 0; i < result.size(); i++) {
                result[i] ^= 0x5A;  // 简单 XOR 变换
            }
            return result;
        } catch (...) {
            return "";
        }
    }

    // 第二层异常控制：密钥派生也藏在 catch 里
    std::string deriveKey(const std::string& seed) {
        try {
            if (seed.empty()) throw std::invalid_argument("empty");
            // 正常路径返回空
            return "";
        } catch (const std::invalid_argument&) {
            // 真正的密钥派生
            std::string key = seed;
            for (size_t i = 0; i < key.size(); i++) {
                key[i] = key[i] ^ 0x3C;
            }
            return key;
        } catch (...) {
            return "";
        }
    }
};

// ==================== CipherFactory：vtable 分发 ====================
class ICipher {
public:
    virtual ~ICipher() {}
    virtual std::string encrypt(const std::string& data) = 0;
    virtual std::string name() const = 0;
};

// 诱饵加密器
class NullCipher : public ICipher {
public:
    std::string encrypt(const std::string& data) override { return data; }
    std::string name() const override { return "null"; }
};

// 诱饵加密器2
class XorCipher : public ICipher {
    uint8_t key_;
public:
    XorCipher(uint8_t k = 0xFF) : key_(k) {}
    std::string encrypt(const std::string& data) override {
        std::string r = data;
        for (auto& c : r) c ^= key_;
        return r;
    }
    std::string name() const override { return "xor"; }
};

static std::string core_feistel_encrypt(const std::string& data);

// 真加密器：还原 ErrorHandler 的 XOR 掩码后调用 libnative53c.so 的 Feistel 核心
class AesFeistelEngine : public ICipher {
public:
    std::string encrypt(const std::string& data) override {
        std::string plain = data;
        for (size_t i = 0; i < plain.size(); i++) plain[i] ^= 0x5A;
        return core_feistel_encrypt(plain);
    }
    std::string name() const override { return "aes53"; }
};

class CipherFactory {
public:
    // 根据 algo_id 创建加密器——vtable 分发
    static ICipher* create(int algo_id) {
        if (algo_id == 1 || algo_id == 2) return new AesFeistelEngine();
        // fallback：返回诱饵
        switch (algo_id) {
            case 0: return new NullCipher();
            default: return new NullCipher();
        }
    }
};

// ==================== HMAC-SHA256 ====================
static uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t sha256_h0[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
};

static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    for (int i = 0; i < 16; i++)
        W[i] = (block[i*4] << 24) | (block[i*4+1] << 16) | (block[i*4+2] << 8) | block[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(W[i-15], 7) ^ rotr32(W[i-15], 18) ^ (W[i-15] >> 3);
        uint32_t s1 = rotr32(W[i-2], 17) ^ rotr32(W[i-2], 19) ^ (W[i-2] >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }
    uint32_t a=state[0],b=state[1],c=state[2],d=state[3],e=state[4],f=state[5],g=state[6],h=state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1=rotr32(e,6)^rotr32(e,11)^rotr32(e,25), ch=(e&f)^(~e&g);
        uint32_t t1=h+S1+ch+sha256_k[i]+W[i];
        uint32_t S0=rotr32(a,2)^rotr32(a,13)^rotr32(a,22), maj=(a&b)^(a&c)^(b&c);
        uint32_t t2=S0+maj;
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;
    state[4]+=e;state[5]+=f;state[6]+=g;state[7]+=h;
}

static std::string sha256_hash(const std::string& msg) {
    uint32_t state[8]; memcpy(state, sha256_h0, sizeof(state));
    uint64_t bit_len = msg.size() * 8;
    std::string padded = msg; padded += (char)0x80;
    while (padded.size() % 64 != 56) padded += (char)0x00;
    for (int i = 7; i >= 0; i--) padded += (char)((bit_len >> (i * 8)) & 0xFF);
    for (size_t i = 0; i < padded.size(); i += 64) {
        uint8_t block[64]; memcpy(block, padded.c_str() + i, 64);
        sha256_compress(state, block);
    }
    std::string result(32, '\0');
    for (int i = 0; i < 8; i++) {
        result[i*4]=(state[i]>>24)&0xFF; result[i*4+1]=(state[i]>>16)&0xFF;
        result[i*4+2]=(state[i]>>8)&0xFF; result[i*4+3]=state[i]&0xFF;
    }
    return result;
}

static std::string hmac_sha256(const std::string& key, const std::string& msg) {
    std::string k = key.size() > 64 ? sha256_hash(key) : key;
    while (k.size() < 64) k += '\0';
    std::string ipad(64, 0x36), opad(64, 0x5C);
    for (int i = 0; i < 64; i++) { ipad[i] ^= k[i]; opad[i] ^= k[i]; }
    return sha256_hash(opad + sha256_hash(ipad + msg));
}

// ==================== XOR 密钥（本地 fallback） ====================
// ==================== XOR 密钥（本地 fallback，正常由 libnative53c 提供） ====================
uint8_t K53_HMAC_XOR[] = {
    0x7a,0x5d,0x48,0x58,0x53,0x5b,0x63,0x54,
    0x51,0x5d,0x5f,0x63,0x57,0x09,0x0f,0x3c
};
static const uint8_t K53_XOR = 0x3C;

static std::string get_hmac_key_local() {
    std::string key(16, '\0');
    for (int i = 0; i < 16; i++) key[i] = K53_HMAC_XOR[i] ^ K53_XOR;
    return key;
}

static void* g_53c_handle = nullptr;
static feistel_core_fn g_feistel_fn = nullptr;
static rc4_core_fn g_rc4_fn = nullptr;

static void ensure53cCore() {
    if (g_53c_handle) return;
    g_53c_handle = dlopen("libnative53c.so", RTLD_NOW);
    if (!g_53c_handle) return;
    g_feistel_fn = (feistel_core_fn)dlsym(g_53c_handle, "k53FeistelEncrypt");
    g_rc4_fn = (rc4_core_fn)dlsym(g_53c_handle, "k53Rc4Crypt");
}

static std::string core_feistel_encrypt(const std::string& data) {
    ensure53cCore();
    if (!g_feistel_fn) return "";
    std::vector<uint8_t> out(data.size() + 32);
    int outLen = 0;
    if (g_feistel_fn((const uint8_t*)data.data(), (int)data.size(),
                     out.data(), (int)out.size(), &outLen) != 0 || outLen <= 0)
        return "";
    return std::string((const char*)out.data(), outLen);
}

// ==================== 深层调用栈辅助函数 ====================
static std::string k53_dispatch(int algo_id, const std::string& data) {
    // 第2层
    ErrorHandler handler;
    std::string processed = handler.process(data);
    // 第3层
    ICipher* cipher = CipherFactory::create(algo_id);
    std::string result = cipher->encrypt(processed);
    delete cipher;
    return result;
}

// ==================== JNI 函数（静态命名 → RegisterNatives 动态绑定） ====================
static JavaVM* g_jvm = nullptr;

static jstring nativeSign53(JNIEnv* env, jobject, jstring data) {
    const char* cdata = env->GetStringUTFChars(data, nullptr);
    std::string payload(cdata);
    env->ReleaseStringUTFChars(data, cdata);

    // 从 libnative53c.so 获取 HMAC key
    std::string hmac_key;
    void* handle = dlopen("libnative53c.so", RTLD_NOW);
    if (handle) {
        get_key_func fn = (get_key_func)dlsym(handle, "getHmacKey");
        if (fn) {
            const uint8_t* raw = fn();
            if (raw) hmac_key = std::string(reinterpret_cast<const char*>(raw), 16);
        }
        dlclose(handle);
    }
    if (hmac_key.empty()) hmac_key = get_hmac_key_local();

    std::string sig = hmac_sha256(hmac_key, payload);
    std::string hex;
    for (unsigned char c : sig) { char buf[3]; snprintf(buf, sizeof(buf), "%02x", c); hex += buf; }
    return env->NewStringUTF(hex.c_str());
}

static jstring nativeEnc53(JNIEnv* env, jobject, jstring data, jint algo) {
    const char* cdata = env->GetStringUTFChars(data, nullptr);
    std::string input(cdata);
    env->ReleaseStringUTFChars(data, cdata);

    // 深层调用栈：JNI → k53_dispatch → ErrorHandler::process → CipherFactory::create → encrypt
    std::string enc = k53_dispatch(algo, input);

    std::string hex;
    for (unsigned char c : enc) { char buf[3]; snprintf(buf, sizeof(buf), "%02x", c); hex += buf; }
    return env->NewStringUTF(hex.c_str());
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static jstring nativeRc4Decrypt53(JNIEnv* env, jobject, jstring hexData) {
    const char* cdata = env->GetStringUTFChars(hexData, nullptr);
    std::string hex(cdata);
    env->ReleaseStringUTFChars(hexData, cdata);
    if (hex.size() % 2 != 0) return env->NewStringUTF("");
    std::vector<uint8_t> in(hex.size() / 2);
    for (size_t i = 0; i < in.size(); i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return env->NewStringUTF("");
        in[i] = (uint8_t)((hi << 4) | lo);
    }
    ensure53cCore();
    if (!g_rc4_fn) return env->NewStringUTF("");
    std::vector<uint8_t> out(in.size());
    int outLen = 0;
    if (g_rc4_fn(in.data(), (int)in.size(), out.data(), (int)out.size(), &outLen) != 0 || outLen <= 0)
        return env->NewStringUTF("");
    std::string plain((const char*)out.data(), outLen);
    return env->NewStringUTF(plain.c_str());
}

// ==================== RegisterNatives 动态绑定 ====================

static const JNINativeMethod gMethods53[] = {
    {"nativeSign", "(Ljava/lang/String;)Ljava/lang/String;", (void*)nativeSign53},
    {"nativeEnc",  "(Ljava/lang/String;I)Ljava/lang/String;", (void*)nativeEnc53},
    {"nativeRc4Decrypt", "(Ljava/lang/String;)Ljava/lang/String;", (void*)nativeRc4Decrypt53},
};

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_jvm = vm;
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass cls = env->FindClass("com/fatdog/reverse/Bk53");
    if (!cls) return JNI_ERR;
    if (env->RegisterNatives(cls, gMethods53, 3) != JNI_OK) return JNI_ERR;
    LOGI("JNI_OnLoad: L53 initialized (RegisterNatives dynamic)");
    return JNI_VERSION_1_6;
}
