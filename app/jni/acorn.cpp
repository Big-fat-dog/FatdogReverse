/*
 * 昆仑山 KL3 渡鸦桥 · 门面 so（六枚中**唯一**导出 Java_ 符号者）。
 *
 * 职责：
 *   ① String 回调 → Ku3.halfA() 取前段明文（"Fatdog_"）；
 *   ② int   回调 → Ku3.bridgeSeed() 取状态初值（链上各内核的片段选择由它播种）；
 *   ③ 依次 dlsym 摘取五枚内核，每枚供 1 字符拼出尾段；
 *   ④ 前段‖尾段 即 nativeKey() 返回值。
 *
 * 断链设计：任一内核缺失（或把 so 抽换掉）→ 立即返回 "ERR_CHAIN"；
 *           callVerbose 下 unidbg 会打印未实现的回调，照着补即可。
 *
 * 答案（真）：前段（Java 回调提供的 String）‖ 五内核各供的 1 字符 —— 完整串见 SOLUTIONS 题解。
 *           （勿在本文件里拼出完整明文，避免源码外泄直接秒题。）
 */
#include <cstddef>
#include <cstdint>
#include <string>
#include <array>

#include "kunlun_chain.h"

#ifndef KU3_HOST_TEST
#include <jni.h>
#include <dlfcn.h>
#endif

namespace {

using relay_fn = int (*)(std::uint32_t, std::uint32_t*);

/* 链序：符号名与时序一一对应（缺一枚即在此处解析失败） */
constexpr std::array<const char*, 5> kChainSym = {
    "ku3_ry_bramble", "ku3_ry_cinder", "ku3_ry_drift", "ku3_ry_elder", "ku3_ry_fable"
};

#ifndef KU3_HOST_TEST
/* 同名 so 兜底：RTLD_DEFAULT 取不到时按 soname 再 dlopen 一次（覆盖命名空间差异） */
constexpr std::array<const char*, 5> kChainSon = {
    "libbramble.so", "libcinder.so", "libdrift.so", "libelder.so", "libfable.so"
};
#endif

#ifdef KU3_HOST_TEST
/* 宿主自测：六个 TU 编进同一进程，直接取址，不经动态链接 */
extern "C" int ku3_ry_bramble(std::uint32_t, std::uint32_t*);
extern "C" int ku3_ry_cinder(std::uint32_t, std::uint32_t*);
extern "C" int ku3_ry_drift(std::uint32_t, std::uint32_t*);
extern "C" int ku3_ry_elder(std::uint32_t, std::uint32_t*);
extern "C" int ku3_ry_fable(std::uint32_t, std::uint32_t*);

constexpr std::array<relay_fn, 5> kDirect = {
    &ku3_ry_bramble, &ku3_ry_cinder, &ku3_ry_drift, &ku3_ry_elder, &ku3_ry_fable
};

int g_skip = -1; /* 宿主专用：置为下标以模拟"某一枚 so 缺失" */
#endif

[[nodiscard]] relay_fn resolve(std::size_t i) noexcept {
#ifdef KU3_HOST_TEST
    if (static_cast<int>(i) == g_skip) return nullptr;
    return kDirect[i];
#else
    if (auto* f = reinterpret_cast<relay_fn>(dlsym(RTLD_DEFAULT, kChainSym[i]))) return f;
    if (void* h = dlopen(kChainSon[i], RTLD_NOW)) {
        return reinterpret_cast<relay_fn>(dlsym(h, kChainSym[i]));
    }
    return nullptr;
#endif
}

/* 纯逻辑：前段 + 沿链取五片 → 完整密钥（或断链错误串）。宿主自测直接调它。 */
[[nodiscard]] std::string assemble(const std::string& head, std::uint32_t seed) {
    std::string tail;
    tail.reserve(kChainSym.size());
    std::uint32_t s = seed;
    for (std::size_t i = 0; i < kChainSym.size(); ++i) {
        relay_fn f = resolve(i);
        if (!f) return std::string("ERR_CHAIN");
        std::uint32_t next = 0;
        const int c = f(s, &next);
        tail.push_back(static_cast<char>(c & 0xFF));
        s = next;
    }
    return head + tail;
}

} // namespace

#ifndef KU3_HOST_TEST

/*
 * Ku3.nativeKey() —— 先取两类 Java 回调，再沿链接力。
 * 顺序固定：String 在前、int 在后（两支都得补，缺一即拼错）。
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Ku3_nativeKey(JNIEnv* env, jclass clazz) {
    /* ① String 回调：前段明文 */
    jmethodID midA = env->GetStaticMethodID(clazz, "halfA", "()Ljava/lang/String;");
    if (!midA) return env->NewStringUTF("ERR_NO_METHOD_A");
    auto* ja = static_cast<jstring>(env->CallStaticObjectMethod(clazz, midA));
    if (!ja) return env->NewStringUTF("ERR_NULL_A");
    const char* a = env->GetStringUTFChars(ja, nullptr);
    std::string head = a ? std::string(a) : std::string();
    if (a) env->ReleaseStringUTFChars(ja, a);
    env->DeleteLocalRef(ja);

    /* ② int 回调：状态初值 */
    jmethodID midB = env->GetStaticMethodID(clazz, "bridgeSeed", "()I");
    if (!midB) return env->NewStringUTF("ERR_NO_METHOD_B");
    const jint seed = env->CallStaticIntMethod(clazz, midB);

    const std::string key = assemble(head, static_cast<std::uint32_t>(seed));
    return env->NewStringUTF(key.c_str());
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void)vm;
    (void)reserved;
    return JNI_VERSION_1_6;
}

#else /* KU3_HOST_TEST */

#include <cstdio>

int main() {
    constexpr std::uint32_t kSeed = 0x20260303u; /* == Ku3.bridgeSeed() */
    std::string good = assemble("Fatdog_", kSeed);
    std::string wrong = assemble("Fatdog_", 0u); /* 未补 int 回调时 unidbg 默认给 0 */
    g_skip = 2;                                  /* 抽掉 drift */
    std::string broken = assemble("Fatdog_", kSeed);
    g_skip = -1;

    /* 结构化断言：前段 "Fatdog_" + 5 个小写字母尾段（诱饵是大写/数字，故能区分） */
    bool shape = (good.size() == 12) && (good.compare(0, 7, "Fatdog_") == 0);
    for (std::size_t i = 7; shape && i < good.size(); ++i) {
        shape = (good[i] >= 'a' && good[i] <= 'z');
    }

    std::printf("canonical  = %s\n", good.c_str());
    std::printf("seed=0     = %s  (expect differs)\n", wrong.c_str());
    std::printf("chain-less = %s  (expect ERR_CHAIN)\n", broken.c_str());

    const bool ok = shape && (wrong != good) && (broken == "ERR_CHAIN");
    std::printf("KU3 SELFTEST %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

#endif /* KU3_HOST_TEST */
