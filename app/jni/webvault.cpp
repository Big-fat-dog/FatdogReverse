/**
 * webvault.cpp — KL42 沙中藏贝（须弥界 · H5 资源加密 + JS 层加密）
 *
 * 考点：
 *   1. H5 资源（HTML + 前端 JS）以加密容器存于 assets/h5/vault_kl42.bin，运行时才解密载入 WebView
 *   2. 解密算法（RC4）与容器钥匙藏在本 so 的异或数组里，运行时还原
 *   3. 解密出来的前端 JS 被 obfuscator 混淆，真·签名密钥在 JS 里——另一层的活儿
 *
 * 钥匙体系：
 *   - 容器钥匙：^0x3C 异或数组 → "Fatdog_vault"（本关资源层的真钥）
 *   - 诱饵钥匙：^0x3C 异或数组 → "Fatdog_shore"（服务端拒签）
 *   - （签名密钥 "Fatdog_reef" 不在 so 里，藏在被混淆的前端 JS 里）
 *
 * 宿主自测：g++ -DWEBVAULT_HOST_TEST 编译后做 RC4 往返自证。
 */

#include <string>
#include <cstring>
#include <cstdint>
#include <cstdio>

#ifdef WEBVAULT_HOST_TEST
  #define LOGI(...) do { printf(__VA_ARGS__); printf("\n"); } while (0)
  #define LOGW(...) do { printf(__VA_ARGS__); printf("\n"); } while (0)
#else
  #include <jni.h>
  #include <android/log.h>
  #define LOG_TAG "WEBVAULT"
  #define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
  #define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#endif

/* ==================== 钥匙（异或数组，运行时还原；volatile 防常量折叠） ==================== */

/* 容器钥匙 ^0x3C —— "Fatdog_vault" */
static const volatile uint8_t BOX_KEY[] = {
    122, 93, 72, 88, 83, 91, 99, 74, 93, 73, 80, 72
};

/* 诱饵钥匙 ^0x3C —— "Fatdog_shore" */
static const volatile uint8_t DECOY_KEY[] = {
    122, 93, 72, 88, 83, 91, 99, 79, 84, 83, 78, 89
};

static std::string decodeKey(const volatile uint8_t* arr, size_t len) {
    std::string r;
    r.reserve(len);
    for (size_t i = 0; i < len; i++) r += (char)(arr[i] ^ 0x3C);
    return r;
}

/* ==================== RC4 ==================== */

static void rc4Crypt(const uint8_t* key, size_t klen,
                     const uint8_t* in, size_t n, uint8_t* out) {
    uint8_t S[256];
    for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) & 0xFF;
        uint8_t t = S[i]; S[i] = (uint8_t)j; S[j] = t;
    }
    int i2 = 0, j2 = 0;
    for (size_t k = 0; k < n; k++) {
        i2 = (i2 + 1) & 0xFF;
        j2 = (j2 + S[i2]) & 0xFF;
        uint8_t t = S[i2]; S[i2] = (uint8_t)j2; S[j2] = t;
        out[k] = in[k] ^ S[(S[i2] + S[j2]) & 0xFF];
    }
}

/* ==================== 宿主自测 ==================== */
#ifdef WEBVAULT_HOST_TEST

int main() {
    std::string key = decodeKey(BOX_KEY, sizeof(BOX_KEY));
    std::string decoy = decodeKey(DECOY_KEY, sizeof(DECOY_KEY));
    printf("box key   = %s\n", key.c_str());
    printf("decoy key = %s\n", decoy.c_str());
    const char* msg = "vault-roundtrip-check";
    size_t n = strlen(msg);
    uint8_t enc[64], dec[64];
    rc4Crypt((const uint8_t*)key.data(), key.size(), (const uint8_t*)msg, n, enc);
    rc4Crypt((const uint8_t*)key.data(), key.size(), enc, n, dec);
    dec[n] = 0;
    printf("cipher id = RC4\n");
    printf("roundtrip = %s (%s)\n", (char*)dec, strcmp((char*)dec, msg) == 0 ? "OK" : "FAIL");
    return 0;
}

#else

/* ==================== JNI 导出 ==================== */
extern "C" {

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_WebVault_nativeDecryptAsset
        (JNIEnv* env, jclass, jbyteArray enc) {
    if (enc == nullptr) return env->NewStringUTF("");
    jsize n = env->GetArrayLength(enc);
    jbyte* p = env->GetByteArrayElements(enc, nullptr);
    std::string key = decodeKey(BOX_KEY, sizeof(BOX_KEY));
    std::string out;
    out.resize((size_t)n);
    if (n > 0) {
        rc4Crypt((const uint8_t*)key.data(), key.size(),
                 (const uint8_t*)p, (size_t)n, (uint8_t*)&out[0]);
    }
    env->ReleaseByteArrayElements(enc, p, JNI_ABORT);
    return env->NewStringUTF(out.c_str());
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_WebVault_nativeGetResourceCipher
        (JNIEnv* env, jclass) {
    return env->NewStringUTF("RC4");
}

JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_WebVault_nativeDecoyKey
        (JNIEnv* env, jclass) {
    std::string d = decodeKey(DECOY_KEY, sizeof(DECOY_KEY));
    return env->NewStringUTF(d.c_str());
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;
    LOGI("webvault loaded");
    return JNI_VERSION_1_6;
}

} /* extern "C" */
#endif
