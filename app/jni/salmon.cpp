/*
 * libsalmon.so — Salmon 业务模块
 *
 * 独立业务库；JNI 侧走 RegisterNatives 动态绑定。
 */

#include <jni.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <utility>
#include <functional>
#include <algorithm>

namespace salmon {

class SalmonCodec {
public:
    explicit SalmonCodec(uint32_t salt) : salt_(salt) {}
    std::string encode(const std::string& in) const {
        std::string out = in;
        for (size_t i = 0; i < out.size(); ++i) {
            uint8_t k = (uint8_t)((salt_ >> ((i & 3) * 8)) & 0xFF);
            out[i] = (char)((uint8_t)((uint8_t)out[i] ^ k) + (uint8_t)(i & 0x1F));
        }
        return out;
    }
    std::string decode(const std::string& in) const {
        std::string out = in;
        for (size_t i = 0; i < out.size(); ++i) {
            uint8_t k = (uint8_t)((salt_ >> ((i & 3) * 8)) & 0xFF);
            out[i] = (char)((uint8_t)((uint8_t)out[i] - (uint8_t)(i & 0x1F)) ^ k);
        }
        return out;
    }
    uint32_t salt() const { return salt_; }
private:
    uint32_t salt_;
};

} /* namespace salmon */

__attribute__((unused)) static std::string jstr_to_std(JNIEnv* env, jstring s) {
    if (s == nullptr) return std::string();
    const char* c = env->GetStringUTFChars(s, nullptr);
    std::string out = (c != nullptr) ? std::string(c) : std::string();
    if (c != nullptr) env->ReleaseStringUTFChars(s, c);
    return out;
}

__attribute__((unused)) static uint32_t mix_scalar(const std::string& in, uint32_t salt) {
    uint32_t a = 0x811C9DC5u ^ salt;
    for (size_t i = 0; i < in.size(); ++i) {
        a ^= (uint8_t)in[i];
        a *= 16777619u;
    }
    uint32_t b = a ^ 0x9E3779B9u;
    b = (b << 5 | b >> 27) ^ (a + 0x27D4EB2Du);
    return b ^ (uint32_t)in.size();
}

__attribute__((unused)) static std::string mix_hex(const std::string& in, uint32_t salt, int words) {
    uint32_t a = 0x811C9DC5u ^ salt;
    uint32_t b = a ^ 0x9E3779B9u;
    std::string out;
    char buf[16];
    for (int i = 0; i < words; ++i) {
        b = (b << 5 | b >> 27) ^ (a + (uint32_t)(i * 0x27D4EB2Du));
        a = (a << 13 | a >> 19) + (b ^ 0x165667B1u);
        snprintf(buf, sizeof(buf), "%08x", b);
        out += buf;
    }
    return out;
}

static jstring j_nLeap(JNIEnv* env, jobject, jint a0) {
    std::string in;
    in += std::to_string((long long)a0);
    salmon::SalmonCodec codec(968038239u);
    in = codec.decode(codec.encode(in));
    std::string hex = mix_hex(in, 968038239u, 4);
    return env->NewStringUTF(hex.c_str());
}

static const JNINativeMethod gMethods[] = {
    {"nativeLeap", "(I)Ljava/lang/String;", (void*)j_nLeap},
};

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK) {
        jclass cls = env->FindClass("com/fatdog/reverse/Bk51");
        if (cls != nullptr) {
            if (env->RegisterNatives(cls, gMethods, 1) != JNI_OK && env->ExceptionCheck())
                env->ExceptionClear();
        } else if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
    }
    return JNI_VERSION_1_6;
}
