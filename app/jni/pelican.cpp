/*
 * libpelican.so — Pelican 业务模块
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

namespace pelican {

class PelicanScheduler {
public:
    void push(int priority, uint32_t task) {
        heap_.push_back(std::make_pair(priority, task));
        std::push_heap(heap_.begin(), heap_.end(), std::greater<std::pair<int, uint32_t> >());
    }
    uint32_t pop() {
        if (heap_.empty()) return 0u;
        std::pop_heap(heap_.begin(), heap_.end(), std::greater<std::pair<int, uint32_t> >());
        uint32_t task = heap_.back().second;
        heap_.pop_back();
        return task;
    }
    size_t size() const { return heap_.size(); }
private:
    std::vector<std::pair<int, uint32_t> > heap_;
};

} /* namespace pelican */

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

static jstring j_nDigest(JNIEnv* env, jobject, jstring a0) {
    std::string in;
    in += jstr_to_std(env, a0);
    pelican::PelicanScheduler sched;
    sched.push(2, (uint32_t)in.size());
    sched.push(1, (uint32_t)(in.size() + 1));
    in += std::to_string((long long)sched.pop());
    std::string hex = mix_hex(in, 2541004877u, 8);
    return env->NewStringUTF(hex.c_str());
}

static const JNINativeMethod gMethods[] = {
    {"nativeDigest", "(Ljava/lang/String;)Ljava/lang/String;", (void*)j_nDigest},
};

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK) {
        jclass cls = env->FindClass("com/fatdog/reverse/Bk48");
        if (cls != nullptr) {
            if (env->RegisterNatives(cls, gMethods, 1) != JNI_OK && env->ExceptionCheck())
                env->ExceptionClear();
        } else if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
    }
    return JNI_VERSION_1_6;
}
