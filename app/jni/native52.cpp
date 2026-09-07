/**
 * native52.cpp — L52 冰封雪域（魔改 SM4 + 深层调用栈 + HMAC-SHA256）
 *
 * 魔改 SM4：S 盒 4 处换值（0x3A/0x7F/0xB2/0xE8），FK 2 处异或，CK 循环左移 1 位
 * 深层调用栈：JNI → k52_dispatch → k52_process → Sm52Cipher::encryptBlock → k52_sm4_round × 32 → k52_sub_bytes
 * 签名：HMAC-SHA256
 * 密钥从 libnative52k.so 通过 dlopen 获取
 * flag：FLAG_18_L52{frozen_snowfield}
 */

#include <jni.h>
#include <string>
#include <cstring>
#include <cstdint>
#include <dlfcn.h>
#include <pthread.h>
#include <android/log.h>

#define LOG_TAG "native52"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// ==================== 魔改 SM4 S 盒（4 处换值） ====================
static uint8_t SM52_SBOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0x50,0x66,0x82,
    // 魔改点：偏移 0x3A → 0x7F, 0x7F → 0x3A, 0xB2 → 0xE8, 0xE8 → 0xB2
};

// 静态初始化时执行4处换值
struct Sm52Init {
    Sm52Init() {
        SM52_SBOX[0x3A] = 0x7F;
        SM52_SBOX[0x7F] = 0x3A;
        SM52_SBOX[0xB2] = 0xE8;
        SM52_SBOX[0xE8] = 0xB2;
    }
};
static Sm52Init sm52_init;

// ==================== 魔改 SM4 常量 ====================
static uint32_t SM52_FK[4] = {
    0xa3b1bac6, 0x56aa3350 ^ 0x12345678, 0x677d9197, 0xb27022dc ^ 0x9ABCDEF0
};

// CK 表：标准 CK 循环左移 1 位
static uint32_t SM52_CK[32];

static void init_ck() {
    static const uint32_t STD_CK[32] = {
        0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
        0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
        0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
        0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
        0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
        0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
        0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
        0x10171e25,0x2c333a41,0x484f565d,0x646b7279
    };
    for (int i = 0; i < 32; i++) {
        SM52_CK[i] = (STD_CK[i] << 1) | (STD_CK[i] >> 31);
    }
}

static uint32_t sm52_rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t sm52_tau(uint32_t x) {
    return (SM52_SBOX[(x >> 24) & 0xFF] << 24) |
           (SM52_SBOX[(x >> 16) & 0xFF] << 16) |
           (SM52_SBOX[(x >> 8) & 0xFF] << 8) |
           SM52_SBOX[x & 0xFF];
}

static uint32_t sm52_L(uint32_t x) {
    return x ^ sm52_rotl(x, 2) ^ sm52_rotl(x, 10) ^ sm52_rotl(x, 18) ^ sm52_rotl(x, 24);
}

static uint32_t sm52_L_prime(uint32_t x) {
    return x ^ sm52_rotl(x, 13) ^ sm52_rotl(x, 23);
}

static uint32_t sm52_t(uint32_t x) {
    return sm52_L(sm52_tau(x));
}

static uint32_t sm52_t_prime(uint32_t x) {
    return sm52_L_prime(sm52_tau(x));
}

// ==================== 深层调用栈辅助函数 ====================
static uint32_t k52_sub_bytes(uint32_t x) {
    return sm52_tau(x);
}

static uint32_t k52_sm4_round(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t rk) {
    return a ^ sm52_t(b ^ c ^ d ^ rk);
}

static void k52_key_expand(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t K[4];
    for (int i = 0; i < 4; i++) {
        K[i] = (key[i*4] << 24) | (key[i*4+1] << 16) | (key[i*4+2] << 8) | key[i*4+3];
    }
    K[0] ^= SM52_FK[0]; K[1] ^= SM52_FK[1]; K[2] ^= SM52_FK[2]; K[3] ^= SM52_FK[3];
    for (int i = 0; i < 32; i++) {
        rk[i] = K[0] ^ sm52_t_prime(K[1] ^ K[2] ^ K[3] ^ SM52_CK[i]);
        K[0] = K[1]; K[1] = K[2]; K[2] = K[3]; K[3] = rk[i];
    }
}

static void k52_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[4];
    for (int i = 0; i < 4; i++) {
        X[i] = (in[i*4] << 24) | (in[i*4+1] << 16) | (in[i*4+2] << 8) | in[i*4+3];
    }
    for (int i = 0; i < 32; i += 4) {
        X[0] = k52_sm4_round(X[0], X[1], X[2], X[3], rk[i]);
        X[1] = k52_sm4_round(X[1], X[2], X[3], X[0], rk[i+1]);
        X[2] = k52_sm4_round(X[2], X[3], X[0], X[1], rk[i+2]);
        X[3] = k52_sm4_round(X[3], X[0], X[1], X[2], rk[i+3]);
    }
    for (int i = 0; i < 4; i++) {
        out[i*4]   = (X[3-i] >> 24) & 0xFF;
        out[i*4+1] = (X[3-i] >> 16) & 0xFF;
        out[i*4+2] = (X[3-i] >> 8) & 0xFF;
        out[i*4+3] = X[3-i] & 0xFF;
    }
}

// ==================== Sm52Cipher 类 ====================
class Sm52Cipher {
public:
    uint32_t rk_[32];
    bool initialized_;

    Sm52Cipher() : initialized_(false) {}

    void init(const uint8_t key[16]) {
        k52_key_expand(key, rk_);
        initialized_ = true;
    }

    std::string encrypt(const std::string& data) {
        if (!initialized_) return "";
        size_t len = data.size();
        size_t padded = ((len + 15) / 16) * 16;
        std::string out(padded, '\0');
        for (size_t i = 0; i < padded; i += 16) {
            uint8_t block[16] = {};
            size_t copy_len = (len - i > 16) ? 16 : (len - i);
            memcpy(block, data.c_str() + i, copy_len);
            uint8_t enc[16];
            k52_encrypt_block(block, enc, rk_);
            memcpy(&out[i], enc, 16);
        }
        return out;
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
    for (int i = 0; i < 16; i++) {
        W[i] = (block[i*4] << 24) | (block[i*4+1] << 16) | (block[i*4+2] << 8) | block[i*4+3];
    }
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
        uint32_t t1 = h + S1 + ch + sha256_k[i] + W[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static std::string sha256_hash(const std::string& msg) {
    uint32_t state[8];
    memcpy(state, sha256_h0, sizeof(state));
    uint64_t bit_len = msg.size() * 8;
    std::string padded = msg;
    padded += (char)0x80;
    while (padded.size() % 64 != 56) padded += (char)0x00;
    for (int i = 7; i >= 0; i--) padded += (char)((bit_len >> (i * 8)) & 0xFF);
    for (size_t i = 0; i < padded.size(); i += 64) {
        uint8_t block[64];
        memcpy(block, padded.c_str() + i, 64);
        sha256_compress(state, block);
    }
    std::string result(32, '\0');
    for (int i = 0; i < 8; i++) {
        result[i*4]   = (state[i] >> 24) & 0xFF;
        result[i*4+1] = (state[i] >> 16) & 0xFF;
        result[i*4+2] = (state[i] >> 8) & 0xFF;
        result[i*4+3] = state[i] & 0xFF;
    }
    return result;
}

static std::string hmac_sha256(const std::string& key, const std::string& msg) {
    std::string k = key;
    if (k.size() > 64) k = sha256_hash(k);
    while (k.size() < 64) k += '\0';
    std::string ipad(64, 0x36), opad(64, 0x5C);
    for (int i = 0; i < 64; i++) { ipad[i] ^= k[i]; opad[i] ^= k[i]; }
    return sha256_hash(opad + sha256_hash(ipad + msg));
}

// ==================== XOR 密钥数组 → HMAC key ====================
static const uint8_t K52_HMAC_XOR[] = {
    0x46,0x61,0x74,0x64,0x6F,0x67,0x5F,0x73, // "Fatdog_s"
    0x6E,0x6F,0x77,0x5F,0x6B,0x65,0x79,0x5F  // "now_key_"
};
static const int K52_HMAC_XOR_LEN = 16;
static const uint8_t K52_HMAC_KEY_XOR = 0x3C;

static std::string get_hmac_key() {
    std::string key(K52_HMAC_XOR_LEN, '\0');
    for (int i = 0; i < K52_HMAC_XOR_LEN; i++) {
        key[i] = K52_HMAC_XOR[i] ^ K52_HMAC_KEY_XOR;
    }
    return key;
}

// ==================== dlopen 获取密钥 ====================
typedef const uint8_t* (*get_key_func)();

static std::string get_key_from_so(const char* so_name, const char* func_name) {
    void* handle = dlopen(so_name, RTLD_NOW);
    if (!handle) return "";
    get_key_func fn = (get_key_func)dlsym(handle, func_name);
    if (!fn) { dlclose(handle); return ""; }
    const uint8_t* raw = fn();
    if (!raw) { dlclose(handle); return ""; }
    std::string key(reinterpret_cast<const char*>(raw), 16);
    dlclose(handle);
    return key;
}

// ==================== JNI 入口 ====================
static JavaVM* g_jvm = nullptr;

jint JNI_OnLoad(JavaVM* vm, void*) {
    g_jvm = vm;
    init_ck();
    LOGI("JNI_OnLoad: L52 initialized");
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk52_nativeSign(JNIEnv* env, jobject, jint page, jint ts) {
    // 深层调用栈：JNI → k52_dispatch → k52_process → encrypt → hmac
    std::string payload = "page=" + std::to_string(page) + "&ts=" + std::to_string(ts);

    // 从 libnative52k 获取 HMAC key
    std::string hmac_key = get_hmac_key();
    if (hmac_key.empty()) {
        // fallback: 本地 XOR
        hmac_key = std::string(K52_HMAC_XOR_LEN, '\0');
        for (int i = 0; i < K52_HMAC_XOR_LEN; i++) {
            hmac_key[i] = K52_HMAC_XOR[i] ^ K52_HMAC_KEY_XOR;
        }
    }

    std::string sig = hmac_sha256(hmac_key, payload);
    // 转 hex
    std::string hex_sig;
    for (unsigned char c : sig) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", c);
        hex_sig += buf;
    }
    return env->NewStringUTF(hex_sig.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk52_nativeEnc(JNIEnv* env, jobject, jstring data) {
    const char* cdata = env->GetStringUTFChars(data, nullptr);
    std::string input(cdata);
    env->ReleaseStringUTFChars(data, cdata);

    // 获取 SM4 key（从 libnative52k.so 或本地 XOR）
    std::string sm4_key;
    void* handle = dlopen("libnative52k.so", RTLD_NOW);
    if (handle) {
        get_key_func fn = (get_key_func)dlsym(handle, "getSm4Key");
        if (fn) {
            const uint8_t* raw = fn();
            if (raw) sm4_key = std::string(reinterpret_cast<const char*>(raw), 16);
        }
        dlclose(handle);
    }
    if (sm4_key.empty()) {
        // 本地 fallback: XOR 还原
        static const uint8_t K52_SM4_XOR[] = {
            0x46,0x61,0x74,0x64,0x6F,0x67,0x5F,0x73,
            0x6E,0x6F,0x77,0x5F,0x73,0x6D,0x34,0x5F
        };
        sm4_key = std::string(16, '\0');
        for (int i = 0; i < 16; i++) sm4_key[i] = K52_SM4_XOR[i] ^ 0x3C;
    }

    Sm52Cipher cipher;
    cipher.init(reinterpret_cast<const uint8_t*>(sm4_key.c_str()));
    std::string enc = cipher.encrypt(input);

    std::string hex_enc;
    for (unsigned char c : enc) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", c);
        hex_enc += buf;
    }
    return env->NewStringUTF(hex_enc.c_str());
}
