/*
 * libcobra.so — L52 冰封雪域（密钥供给 + 响应流解密）
 *
 * 静态分析视角（导出表只留中性词根）：
 *   cb_seed → SM4 主密钥【头段 12 字节】；尾段 "sm4_" 在 Java（跨层回调拼装）
 *   cb_mark → 签名密钥（16 字节）
 *   cb_pad  → 响应流密钥（16 字节）
 *   原来直白的 getSm4Key / getHmacKey / getRc4Key 已改名；
 *   死导出 deriveKeys 已删除；Java_..Bk52_nativeRc4Decrypt 改成
 *   RegisterNatives 动态注册 → .dynsym 里不再出现 Java_*。
 *
 * 密钥仍藏在 XOR(^0x3C) 数组里，运行时 prime_marks() 还原（volatile 掩码防折叠）。
 */

#include <jni.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdint>

/* ==================== 密钥密文数组（XOR ^0x3C） ==================== */
/* SM4 头段："Fatdog_snow_" 前 12 字节（尾段 "sm4_" 在 Java） */
static const uint8_t K52_SM4_HEAD_XOR[] = {
    0x7A,0x5D,0x48,0x58,0x53,0x5B,0x63,0x4F,0x52,0x53,0x4B,0x63
};

/* 签名密钥："Fatdog_snow_key!" */
static const uint8_t K52_MARK_XOR[] = {
    0x7A,0x5D,0x48,0x58,0x53,0x5B,0x63,0x4F,
    0x52,0x53,0x4B,0x63,0x57,0x59,0x45,0x1D
};

/* 响应流密钥："Fatdog_snow_rc4_" */
static const uint8_t K52_PAD_XOR[] = {
    0x7A,0x5D,0x48,0x58,0x53,0x5B,0x63,0x4F,
    0x52,0x53,0x4B,0x63,0x4E,0x5F,0x08,0x63
};

static const uint8_t K52_XOR = 0x3C;

static uint8_t mark_head[12];   /* SM4 头段 */
static uint8_t mark_key[16];    /* 签名密钥 */
static uint8_t mark_pad[16];    /* 响应流密钥 */
static bool marks_ready = false;

static void prime_marks() {
    if (marks_ready) return;
    volatile uint8_t m = K52_XOR;          /* volatile：防 -O2 把整表折叠回明文 */
    for (int i = 0; i < 12; i++) mark_head[i] = (uint8_t)(K52_SM4_HEAD_XOR[i] ^ m);
    for (int i = 0; i < 16; i++) {
        mark_key[i] = (uint8_t)(K52_MARK_XOR[i] ^ m);
        mark_pad[i] = (uint8_t)(K52_PAD_XOR[i] ^ m);
    }
    marks_ready = true;
}

/* ==================== RC4（响应流） ==================== */
static void rc4_init(uint8_t S[256], const uint8_t* key, int key_len) {
    for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;
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

/* ==================== 内部接口（供 libmoose dlsym） ==================== */
extern "C" {

const uint8_t* cb_seed() { prime_marks(); return mark_head; }   /* 12 字节头段 */
const uint8_t* cb_mark() { prime_marks(); return mark_key;  }   /* 16 字节 */
const uint8_t* cb_pad()  { prime_marks(); return mark_pad;  }   /* 16 字节 */

} /* extern "C" */

/* ==================== JNI：响应解密（RegisterNatives 动态注册） ==================== */
static jstring implRc4(JNIEnv* env, jclass, jstring data) {
    const char* cdata = env->GetStringUTFChars(data, nullptr);
    std::string input = (cdata != nullptr) ? std::string(cdata) : std::string();
    if (cdata != nullptr) env->ReleaseStringUTFChars(data, cdata);

    prime_marks();
    std::string dec = rc4_crypt(mark_pad, 16, input);

    std::string hex;
    for (unsigned char c : dec) { char buf[3]; snprintf(buf, sizeof(buf), "%02x", c); hex += buf; }
    return env->NewStringUTF(hex.c_str());
}

static const JNINativeMethod gMethods[] = {
    {"nativeRc4Decrypt", "(Ljava/lang/String;)Ljava/lang/String;", (void*)implRc4},
};

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    prime_marks();
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK)
        return JNI_VERSION_1_6;   /* 防御式：异常一律不返回 JNI_ERR */
    jclass cls = env->FindClass("com/fatdog/reverse/Bk52");
    if (cls != nullptr) {
        if (env->RegisterNatives(cls, gMethods, 1) != JNI_OK && env->ExceptionCheck())
            env->ExceptionClear();
    } else if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
    return JNI_VERSION_1_6;
}
