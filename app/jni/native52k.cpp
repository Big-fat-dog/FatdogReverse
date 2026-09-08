/**
 * native52k.cpp — L52 冰封雪域（密钥 + RC4 + 响应解密）
 *
 * XOR 数组 → SM4 key + HMAC key + RC4 key
 * RC4 加密/解密响应体
 * 导出函数供 libnative52.so dlopen 调用
 */

#include <jni.h>
#include <string>
#include <cstring>
#include <cstdint>
#include <android/log.h>

#define LOG_TAG "native52k"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// ==================== XOR 密钥数组 ====================
// SM4 key: "Fatdog_snow_sm4_" ^ 0x3C
uint8_t K52_SM4_XOR[] = {
    0x7a,0x5d,0x48,0x58,0x53,0x5b,0x63,0x4f,
    0x52,0x53,0x4b,0x63,0x4f,0x51,0x08,0x63
};
static const uint8_t K52_XOR_KEY = 0x3C;

// HMAC key: "Fatdog_snow_key!" ^ 0x3C
uint8_t K52_HMAC_XOR[] = {
    0x7a,0x5d,0x48,0x58,0x53,0x5b,0x63,0x4f,
    0x52,0x53,0x4b,0x63,0x57,0x59,0x45,0x1d
};

// RC4 key: "Fatdog_snow_rc4_" ^ 0x3C
uint8_t K52_RC4_XOR[] = {
    0x7a,0x5d,0x48,0x58,0x53,0x5b,0x63,0x4f,
    0x52,0x53,0x4b,0x63,0x4e,0x5f,0x08,0x63
};

static uint8_t sm4_key[16];
static uint8_t hmac_key[16];
static uint8_t rc4_key[16];
static bool keys_initialized = false;

static void init_keys() {
    if (keys_initialized) return;
    for (int i = 0; i < 16; i++) {
        sm4_key[i]  = K52_SM4_XOR[i] ^ K52_XOR_KEY;
        hmac_key[i] = K52_HMAC_XOR[i] ^ K52_XOR_KEY;
        rc4_key[i]  = K52_RC4_XOR[i] ^ K52_XOR_KEY;
    }
    keys_initialized = true;
}

// ==================== RC4 ====================
static void rc4_init(uint8_t S[256], const uint8_t* key, int key_len) {
    for (int i = 0; i < 256; i++) S[i] = i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) & 0xFF;
        uint8_t tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
}

static std::string rc4_crypt(const uint8_t* key, int key_len, const std::string& data) {
    uint8_t S[256];
    rc4_init(S, key, key_len);
    std::string out(data.size(), '\0');
    int i = 0, j = 0;
    for (size_t k = 0; k < data.size(); k++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        uint8_t tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        out[k] = data[k] ^ S[(S[i] + S[j]) & 0xFF];
    }
    return out;
}

// ==================== 导出函数（供 dlopen） ====================
extern "C" {

const uint8_t* getSm4Key() {
    init_keys();
    return sm4_key;
}

const uint8_t* getHmacKey() {
    init_keys();
    return hmac_key;
}

const uint8_t* getRc4Key() {
    init_keys();
    return rc4_key;
}

// 密钥派生函数：看似复杂但只是 XOR 展开
const uint8_t* deriveKeys(uint32_t seed) {
    init_keys();
    // 对三组密钥做简单的 seed 混淆（不影响最终值，纯干扰）
    static uint8_t derived[48];
    memcpy(derived, sm4_key, 16);
    memcpy(derived + 16, hmac_key, 16);
    memcpy(derived + 32, rc4_key, 16);
    return derived;
}

} // extern "C"

// ==================== JNI ====================
extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk52_nativeRc4Decrypt(JNIEnv* env, jclass, jstring data) {
    const char* cdata = env->GetStringUTFChars(data, nullptr);
    std::string input(cdata);
    env->ReleaseStringUTFChars(data, cdata);

    init_keys();
    std::string dec = rc4_crypt(rc4_key, 16, input);

    // 转 hex
    std::string hex;
    for (unsigned char c : dec) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", c);
        hex += buf;
    }
    return env->NewStringUTF(hex.c_str());
}

jint JNI_OnLoad(JavaVM* vm, void*) {
    init_keys();
    LOGI("JNI_OnLoad: L52k keys initialized");
    return JNI_VERSION_1_6;
}
