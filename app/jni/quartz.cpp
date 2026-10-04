/*
 * libquartz.so — Quartz 业务模块
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

namespace quartz {

class QuartzLedger {
public:
    void post(const std::string& account, int64_t amount) {
        book_.push_back(std::make_pair(account, amount));
    }
    int64_t balance(const std::string& account) const {
        int64_t sum = 0;
        for (size_t i = 0; i < book_.size(); ++i)
            if (book_[i].first == account) sum += book_[i].second;
        return sum;
    }
    size_t entries() const { return book_.size(); }
private:
    std::vector<std::pair<std::string, int64_t> > book_;
};

} /* namespace quartz */

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

static jstring j_nLattice(JNIEnv* env, jobject, jstring a0) {
    std::string in;
    in += jstr_to_std(env, a0);
    quartz::QuartzLedger ledger;
    ledger.post("main", (int64_t)in.size());
    ledger.post("aux", (int64_t)(in.size() ^ 0x5Au));
    in += std::to_string((long long)ledger.balance("main"));
    std::string hex = mix_hex(in, 2207917150u, 4);
    return env->NewStringUTF(hex.c_str());
}

static const JNINativeMethod gMethods[] = {
    {"nativeLattice", "(Ljava/lang/String;)Ljava/lang/String;", (void*)j_nLattice},
};

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK) {
        jclass cls = env->FindClass("com/fatdog/reverse/Bk49");
        if (cls != nullptr) {
            if (env->RegisterNatives(cls, gMethods, 1) != JNI_OK && env->ExceptionCheck())
                env->ExceptionClear();
        } else if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
    }
    return JNI_VERSION_1_6;
}
