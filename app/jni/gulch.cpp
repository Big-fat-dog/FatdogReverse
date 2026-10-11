/*
 * 昆仑山 KL4 冰裂缝 · 门面 so（六枚中**唯一**导出 Java_ 符号者）。
 *
 * 职责：
 *   ① 反模拟体检：/proc/self/maps 搜 unidbg/unicorn 特征 + /proc/self/status 查 TracerPid；
 *   ② 四类 Java 回调：headMark()(String) / forkSeed()(int) / SPLIT_X(静态 int 字段) / saltPlan()(int[])；
 *   ③ 按菱形数据流 dlsym 摘取五枚内核：iris→kindle、juniper→larch、marrow 归并；
 *   ④ 前段‖尾段 即 nativeProbe() 返回值。
 *
 * 断链设计：任一内核缺失 → "ERR_CHAIN"；盐数组长度≠5 → "ERR_PLAN"；环境脏 → "ERR_EMULATED"。
 *            callVerbose 下 unidbg 会打印未实现的回调/字段，照着补即可。
 *
 * 答案（真）：前段（Java String 回调）‖ 五内核按菱形分叉各供的片段 —— 完整串见 SOLUTIONS 题解。
 *             （勿在本文件里拼出完整明文，避免源码外泄直接秒题。）
 */
#include <cstddef>
#include <cstdint>
#include <string>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "kunlun_fork.h"

#ifndef KU4_HOST_TEST
#include <jni.h>
#include <dlfcn.h>
#endif

namespace {

using seg_fn = int (*)(std::uint32_t, std::uint32_t, char*, int, std::uint32_t*);

/* 链序：符号名与数据流时序一一对应（缺一枚即在此处解析失败） */
constexpr std::array<const char*, 5> kSym = {
    "ku4_ry_iris", "ku4_ry_juniper", "ku4_ry_kindle", "ku4_ry_larch", "ku4_ry_marrow"
};

#ifndef KU4_HOST_TEST
/* 同名 so 兜底：RTLD_DEFAULT 取不到时按 soname 再 dlopen 一次 */
constexpr std::array<const char*, 5> kSon = {
    "libiris.so", "libjuniper.so", "libkindle.so", "liblarch.so", "libmarrow.so"
};
#endif

#ifdef KU4_HOST_TEST
/* 宿主自测：六个 TU 编进同一进程，直接取址，不经动态链接 */
extern "C" int ku4_ry_iris(std::uint32_t, std::uint32_t, char*, int, std::uint32_t*);
extern "C" int ku4_ry_juniper(std::uint32_t, std::uint32_t, char*, int, std::uint32_t*);
extern "C" int ku4_ry_kindle(std::uint32_t, std::uint32_t, char*, int, std::uint32_t*);
extern "C" int ku4_ry_larch(std::uint32_t, std::uint32_t, char*, int, std::uint32_t*);
extern "C" int ku4_ry_marrow(std::uint32_t, std::uint32_t, char*, int, std::uint32_t*);

constexpr std::array<seg_fn, 5> kDirect = {
    &ku4_ry_iris, &ku4_ry_juniper, &ku4_ry_kindle, &ku4_ry_larch, &ku4_ry_marrow
};

int g_skip = -1; /* 宿主专用：置为下标以模拟"某一枚 so 缺失" */
#endif

[[nodiscard]] seg_fn resolve(std::size_t i) noexcept {
#ifdef KU4_HOST_TEST
    if (static_cast<int>(i) == g_skip) return nullptr;
    return kDirect[i];
#else
    if (auto* f = reinterpret_cast<seg_fn>(dlsym(RTLD_DEFAULT, kSym[i]))) return f;
    if (void* h = dlopen(kSon[i], RTLD_NOW)) {
        return reinterpret_cast<seg_fn>(dlsym(h, kSym[i]));
    }
    return nullptr;
#endif
}

/* 纯逻辑：菱形分叉拼密钥（或断链错误串）。宿主自测直接调它。 */
[[nodiscard]] std::string assemble(const std::string& head, std::uint32_t seed,
                                   std::uint32_t mask, const std::uint32_t plan[5]) {
    std::array<seg_fn, 5> fp{};
    for (std::size_t i = 0; i < fp.size(); ++i) {
        fp[i] = resolve(i);
        if (!fp[i]) return std::string("ERR_CHAIN");
    }

    char buf[64];
    int n = 0;
    const int cap = static_cast<int>(sizeof(buf));
    std::uint32_t si = 0, sj = 0, sk = 0, sl = 0, sm = 0;
    const std::uint32_t fork = ku4::step(seed ^ mask);

    /* 菱形：同源分叉 → 两路中继 → 归并（时序错一步即拼错） */
    n += fp[0](fork,    plan[0], buf + n, cap - n, &si); /* iris   → 左支头 */
    n += fp[1](fork,    plan[1], buf + n, cap - n, &sj); /* juniper→ 右支头 */
    n += fp[2](si,      plan[2], buf + n, cap - n, &sk); /* kindle ← 左支中继 */
    n += fp[3](sj,      plan[3], buf + n, cap - n, &sl); /* larch  ← 右支中继 */
    n += fp[4](si ^ sj, plan[4], buf + n, cap - n, &sm); /* marrow ← 归并 */

    (void)sk;
    (void)sl;
    (void)sm;
    return head + std::string(buf, buf + n);
}

} // namespace

#ifndef KU4_HOST_TEST

/* ---------- 反模拟体检（真机天生干净；unidbg 需 IOResolver 喂假文件）---------- */

[[nodiscard]] int probe_maps() {
    FILE* f = std::fopen("/proc/self/maps", "r");
    if (!f) return -1;
    char line[512];
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strstr(line, "unidbg") || std::strstr(line, "unicorn") ||
            std::strstr(line, "gum-js-loop")) {
            std::fclose(f);
            return 1; /* 命中模拟器特征 */
        }
    }
    std::fclose(f);
    return 0;
}

[[nodiscard]] int probe_tracer() {
    FILE* f = std::fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strncmp(line, "TracerPid:", 10) == 0) {
            std::fclose(f);
            return std::atoi(line + 10) != 0 ? 1 : 0;
        }
    }
    std::fclose(f);
    return 0;
}

/* 0 干净 / 1 脏 / -1 IO 失败 */
[[nodiscard]] int env_state() {
    const int m = probe_maps();
    const int t = probe_tracer();
    if (m == 1 || t == 1) return 1;
    if (m < 0 || t < 0) return -1;
    return 0;
}

/*
 * 四类回调依次取齐后再沿菱形分叉拼钥（顺序固定；缺任一路都拼不对）。
 * 返回的错误串直接抛出供 unidbg 玩家按提示补桩。
 */
[[nodiscard]] std::string probe_key(JNIEnv* env, jclass clazz) {
    /* ① String 回调：前段明文 */
    jmethodID mA = env->GetStaticMethodID(clazz, "headMark", "()Ljava/lang/String;");
    if (!mA) return std::string("ERR_NO_METHOD");
    auto* ja = static_cast<jstring>(env->CallStaticObjectMethod(clazz, mA));
    if (!ja) return std::string("ERR_NULL");
    const char* a = env->GetStringUTFChars(ja, nullptr);
    std::string head = a ? std::string(a) : std::string();
    if (a) env->ReleaseStringUTFChars(ja, a);
    env->DeleteLocalRef(ja);

    /* ② int 回调：fork 种子 */
    jmethodID mB = env->GetStaticMethodID(clazz, "forkSeed", "()I");
    if (!mB) return std::string("ERR_NO_METHOD");
    const jint seed = env->CallStaticIntMethod(clazz, mB);

    /* ③ 静态 int 字段：分叉掩码（GetStaticIntField，非方法调用） */
    jfieldID fF = env->GetStaticFieldID(clazz, "SPLIT_X", "I");
    if (!fF) return std::string("ERR_NO_FIELD");
    const jint mask = env->GetStaticIntField(clazz, fF);

    /* ④ int[] 回调：五段盐（返回对象是数组，需按数组读） */
    jmethodID mD = env->GetStaticMethodID(clazz, "saltPlan", "()[I");
    if (!mD) return std::string("ERR_NO_METHOD");
    auto* jarr = static_cast<jintArray>(env->CallStaticObjectMethod(clazz, mD));
    if (!jarr) return std::string("ERR_NULL_PLAN");
    const jsize ln = env->GetArrayLength(jarr);
    if (ln != 5) {
        env->DeleteLocalRef(jarr);
        return std::string("ERR_PLAN");
    }
    jint* elems = env->GetIntArrayElements(jarr, nullptr);
    if (!elems) {
        env->DeleteLocalRef(jarr);
        return std::string("ERR_PLAN");
    }
    std::uint32_t plan[5];
    for (int i = 0; i < 5; ++i) plan[i] = static_cast<std::uint32_t>(elems[i]);
    env->ReleaseIntArrayElements(jarr, elems, JNI_ABORT);
    env->DeleteLocalRef(jarr);

    return assemble(head, static_cast<std::uint32_t>(seed), static_cast<std::uint32_t>(mask), plan);
}

/*
 * Ku4.nativeProbe() —— 先过反模拟体检，再沿菱形分叉拼钥。
 * 真机环境天然干净，直接返回完整密钥；unidbg 需补 IOResolver + 四类回调。
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Ku4_nativeProbe(JNIEnv* env, jclass clazz) {
    const int e = env_state();
    if (e == 1) return env->NewStringUTF("ERR_EMULATED");
    if (e < 0) return env->NewStringUTF("ERR_IO_FAIL");
    return env->NewStringUTF(probe_key(env, clazz).c_str());
}

/*
 * Ku4.nativeSubmit() —— 复检环境，再与现算的密钥比对。
 * 完整校验在 so 内完成且不留明文答案：先过体检，再用同一路径现算一次比较。
 */
extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Ku4_nativeSubmit(JNIEnv* env, jclass clazz, jstring token) {
    if (env_state() != 0 || token == nullptr) return 0;
    const char* u = env->GetStringUTFChars(token, nullptr);
    if (!u) return 0;
    const std::string expect = probe_key(env, clazz);
    const bool ok = (expect == std::string(u));
    env->ReleaseStringUTFChars(token, u);
    return ok ? 1 : 0;
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void)vm;
    (void)reserved;
    return JNI_VERSION_1_6;
}

#else /* KU4_HOST_TEST */

int main() {
    std::uint32_t plan[5];
    for (int i = 0; i < 5; ++i) plan[i] = ku4::SALT[i];

    const std::string good = assemble("Fatdog_", ku4::SEED, ku4::MASK, plan);
    const std::string wrong_seed = assemble("Fatdog_", 0u, ku4::MASK, plan);
    const std::string wrong_mask = assemble("Fatdog_", ku4::SEED, 0u, plan);

    std::uint32_t bad_plan[5] = {ku4::SALT[0], ku4::SALT[1], ku4::SALT[2], ku4::SALT[3], 0u};
    const std::string wrong_plan = assemble("Fatdog_", ku4::SEED, ku4::MASK, bad_plan);

    g_skip = 2; /* 抽掉 kindle（左支中继） */
    const std::string broken = assemble("Fatdog_", ku4::SEED, ku4::MASK, plan);
    g_skip = -1;

    /* 结构化断言：前段 "Fatdog_" + 16 个小写/下划线片段（诱饵是大写/数字，故能区分） */
    bool shape = (good.size() == 23) && (good.compare(0, 7, "Fatdog_") == 0);
    for (std::size_t i = 7; shape && i < good.size(); ++i) {
        const char c = good[i];
        shape = ((c >= 'a' && c <= 'z') || c == '_');
    }

    std::printf("canonical  = %s\n", good.c_str());
    std::printf("seed=0     = %s  (expect differs)\n", wrong_seed.c_str());
    std::printf("mask=0     = %s  (expect differs)\n", wrong_mask.c_str());
    std::printf("plan[-1]   = %s  (expect differs)\n", wrong_plan.c_str());
    std::printf("chain-less = %s  (expect ERR_CHAIN)\n", broken.c_str());

    const bool ok = shape && (wrong_seed != good) && (wrong_mask != good) &&
                    (wrong_plan != good) && (broken == "ERR_CHAIN");
    std::printf("KU4 SELFTEST %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

#endif /* KU4_HOST_TEST */
