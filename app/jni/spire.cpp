/*
 * 昆仑山 KL5 登顶 · 门面 so（六枚中**唯一**导出 Java_ 符号者）。
 *
 * 职责：
 *   ① 三路反模拟体检：/proc/self/maps（搜 unidbg/unicorn/frida/qemu 特征）、
 *      /proc/self/status（TracerPid）、/proc/self/cmdline（搜 unidbg/android_server/frida）；
 *   ② 五类 Java 回调：climbSeed()(int) / baseMark()(String) / SUMMIT_TAG(静态 String 字段)
 *      / peakStamp()(long) / routePlan()(int[]，6 段)；
 *   ③ 以状态揉出 s0 → Fisher–Yates 现算 5 元置换 →「平坦化调度器」沿置换派发五枚内核；
 *   ④ 返回值即 nativeClimb() 的密钥串。
 *
 * 与前两关的关键差异：**内核执行次序不在源码里**——次序由运行时 s0 现算，
 * 藏在 g_next 状态表里；静态读不到。要么补全环境后直接跑出返回值，要么 trace
 * （Frida Stalker / unidbg trace）看 dispatcher 先派发了谁。
 *
 * 断链 / 缺桩错误串：任一内核缺失 → "ERR_CHAIN"；routePlan 长度≠6 → "ERR_PLAN"；
 *                    环境脏 → "ERR_EMULATED"；回调/字段缺失 → "ERR_NO_METHOD"/"ERR_NO_FIELD"。
 *
 * 答案：见 SOLUTIONS 题解（勿在本文件里拼出完整明文，避免源码外泄直接秒题）。
 */
#include <cstddef>
#include <cstdint>
#include <string>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "kunlun_summit.h"

#ifndef KU5_HOST_TEST
#include <jni.h>
#include <dlfcn.h>
#endif

namespace {

using seg_fn = int (*)(std::uint32_t, std::uint32_t, char*, int);

/* 链序：下标即内核号（盐与置换都按此下标索引） */
constexpr std::array<const char*, 5> kSym = {
    "ku5_ry_quarry", "ku5_ry_ridge", "ku5_ry_shard", "ku5_ry_talus", "ku5_ry_verge"
};

#ifndef KU5_HOST_TEST
/* 同名 so 兜底：RTLD_DEFAULT 取不到时按 soname 再 dlopen 一次 */
constexpr std::array<const char*, 5> kSon = {
    "libquarry.so", "libridge.so", "libshard.so", "libtalus.so", "libverge.so"
};
#endif

#ifdef KU5_HOST_TEST
/* 宿主自测：六个 TU 编进同一进程，直接取址，不经动态链接 */
extern "C" int ku5_ry_quarry(std::uint32_t, std::uint32_t, char*, int);
extern "C" int ku5_ry_ridge(std::uint32_t, std::uint32_t, char*, int);
extern "C" int ku5_ry_shard(std::uint32_t, std::uint32_t, char*, int);
extern "C" int ku5_ry_talus(std::uint32_t, std::uint32_t, char*, int);
extern "C" int ku5_ry_verge(std::uint32_t, std::uint32_t, char*, int);

constexpr std::array<seg_fn, 5> kDirect = {
    &ku5_ry_quarry, &ku5_ry_ridge, &ku5_ry_shard, &ku5_ry_talus, &ku5_ry_verge
};

int g_skip = -1; /* 宿主专用：置为下标以模拟"某一枚 so 缺失" */
#endif

[[nodiscard]] seg_fn resolve(std::size_t i) noexcept {
#ifdef KU5_HOST_TEST
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

/* FNV-1a 32：把 String / 静态字段揉进掩码 */
[[nodiscard]] std::uint32_t fnv1a(const std::string& s) noexcept {
    std::uint32_t h = 0x811C9DC5u;
    for (unsigned char c : s) {
        h ^= static_cast<std::uint32_t>(c);
        h *= 0x01000193u;
    }
    return h;
}

/*
 * 纯逻辑：揉状态 → 现算置换 → 平坦化调度器派发内核 → 拼返回串。
 * 宿主自测直接调它。
 */
[[nodiscard]] std::string assemble(std::uint32_t seed, const std::string& bm,
                                   const std::string& tg, std::uint64_t peak,
                                   const std::uint32_t plan[6]) {
    std::array<seg_fn, 5> fp{};
    for (std::size_t i = 0; i < fp.size(); ++i) {
        fp[i] = resolve(i);
        if (!fp[i]) return std::string("ERR_CHAIN");
    }

    const std::uint32_t mask = fnv1a(bm) ^ fnv1a(tg)
                             ^ static_cast<std::uint32_t>(peak)
                             ^ static_cast<std::uint32_t>(peak >> 32)
                             ^ plan[5];
    const std::uint32_t s0 = ku5::step(seed ^ mask);

    int order[5];
    ku5::permute(s0, order);

    char buf[64];
    int n = 0;
    const int cap = static_cast<int>(sizeof(buf));

    /* ---------- 平坦化调度器：状态表 g_next 运行时生成，次序藏在内存里 ---------- */
    std::uint32_t g_order[5] = {0u, 0u, 0u, 0u, 0u};
    std::uint32_t g_next[7] = {0u, 0u, 0u, 0u, 0u, 0u, 0u};
    std::uint32_t st = ku5::S_INIT;

    for (;;) {
        switch (st) {
            case ku5::S_INIT:
                for (int i = 0; i < 5; ++i) g_order[i] = static_cast<std::uint32_t>(order[i]);
                g_next[ku5::S_INIT] = ku5::S_K0 + g_order[0];
                for (int i = 0; i < 4; ++i)
                    g_next[ku5::S_K0 + g_order[i]] = ku5::S_K0 + g_order[i + 1];
                g_next[ku5::S_K0 + g_order[4]] = ku5::S_END;
                st = g_next[st];
                break;
            /* 状态 S_Kj 对应内核 j —— 访问次序由 g_next 决定（j 由置换现算） */
            case ku5::S_K0:
                n += fp[0](s0, plan[0], buf + n, cap - n);
                st = g_next[st];
                break;
            case ku5::S_K1:
                n += fp[1](s0, plan[1], buf + n, cap - n);
                st = g_next[st];
                break;
            case ku5::S_K2:
                n += fp[2](s0, plan[2], buf + n, cap - n);
                st = g_next[st];
                break;
            case ku5::S_K3:
                n += fp[3](s0, plan[3], buf + n, cap - n);
                st = g_next[st];
                break;
            case ku5::S_K4:
                n += fp[4](s0, plan[4], buf + n, cap - n);
                st = g_next[st];
                break;
            case ku5::S_END:
                return std::string(buf, buf + n);
            default:
                return std::string("ERR_STATE");
        }
    }
}

} // namespace

#ifndef KU5_HOST_TEST

/* ---------- 三路反模拟体检（真机天生干净；unidbg 需 IOResolver 喂三份假文件）---------- */

[[nodiscard]] int probe_maps() {
    FILE* f = std::fopen("/proc/self/maps", "r");
    if (!f) return -1;
    char line[512];
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strstr(line, "unidbg") || std::strstr(line, "unicorn") ||
            std::strstr(line, "gum-js-loop") || std::strstr(line, "frida") ||
            std::strstr(line, "qemu")) {
            std::fclose(f);
            return 1; /* 命中模拟/注入特征 */
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

/* 进程名（cmdline）也是模拟器/调试器常暴露的一路 */
[[nodiscard]] int probe_cmdline() {
    FILE* f = std::fopen("/proc/self/cmdline", "r");
    if (!f) return -1;
    char buf[256];
    const std::size_t got = std::fread(buf, 1, sizeof(buf) - 1, f);
    buf[got] = '\0';
    std::fclose(f);
    return (std::strstr(buf, "unidbg") || std::strstr(buf, "android_server") ||
            std::strstr(buf, "frida")) ? 1 : 0;
}

/* 0 干净 / 1 脏 / -1 IO 失败 */
[[nodiscard]] int env_state() {
    const int m = probe_maps();
    const int t = probe_tracer();
    const int c = probe_cmdline();
    if (m == 1 || t == 1 || c == 1) return 1;
    if (m < 0 || t < 0 || c < 0) return -1;
    return 0;
}

/* 五类回调依次取齐后沿平坦化调度器拼钥（顺序固定；缺任一路都拼不对）。 */
[[nodiscard]] std::string probe_key(JNIEnv* env, jclass clazz) {
    /* ① int 回调：种子 */
    jmethodID mS = env->GetStaticMethodID(clazz, "climbSeed", "()I");
    if (!mS) return std::string("ERR_NO_METHOD");
    const jint seed = env->CallStaticIntMethod(clazz, mS);

    /* ② String 回调：掩码分量 ① */
    jmethodID mB = env->GetStaticMethodID(clazz, "baseMark", "()Ljava/lang/String;");
    if (!mB) return std::string("ERR_NO_METHOD");
    auto* jb = static_cast<jstring>(env->CallStaticObjectMethod(clazz, mB));
    if (!jb) return std::string("ERR_NULL");
    const char* cb = env->GetStringUTFChars(jb, nullptr);
    std::string bm = cb ? std::string(cb) : std::string();
    if (cb) env->ReleaseStringUTFChars(jb, cb);
    env->DeleteLocalRef(jb);

    /* ③ 静态 String 字段：掩码分量 ②（字段读取，非方法调用） */
    jfieldID fT = env->GetStaticFieldID(clazz, "SUMMIT_TAG", "Ljava/lang/String;");
    if (!fT) return std::string("ERR_NO_FIELD");
    auto* jt = static_cast<jstring>(env->GetStaticObjectField(clazz, fT));
    if (!jt) return std::string("ERR_NULL");
    const char* ct = env->GetStringUTFChars(jt, nullptr);
    std::string tg = ct ? std::string(ct) : std::string();
    if (ct) env->ReleaseStringUTFChars(jt, ct);
    env->DeleteLocalRef(jt);

    /* ④ long 回调：掩码分量 ③（64 位，高低各掺一半） */
    jmethodID mP = env->GetStaticMethodID(clazz, "peakStamp", "()J");
    if (!mP) return std::string("ERR_NO_METHOD");
    const jlong peak = env->CallStaticLongMethod(clazz, mP);

    /* ⑤ int[] 回调：六段盐（前五段喂内核，第六段掺掩码分量 ④） */
    jmethodID mR = env->GetStaticMethodID(clazz, "routePlan", "()[I");
    if (!mR) return std::string("ERR_NO_METHOD");
    auto* jr = static_cast<jintArray>(env->CallStaticObjectMethod(clazz, mR));
    if (!jr) return std::string("ERR_NULL_PLAN");
    const jsize ln = env->GetArrayLength(jr);
    if (ln != 6) {
        env->DeleteLocalRef(jr);
        return std::string("ERR_PLAN");
    }
    jint* el = env->GetIntArrayElements(jr, nullptr);
    if (!el) {
        env->DeleteLocalRef(jr);
        return std::string("ERR_PLAN");
    }
    std::uint32_t plan[6];
    for (int i = 0; i < 6; ++i) plan[i] = static_cast<std::uint32_t>(el[i]);
    env->ReleaseIntArrayElements(jr, el, JNI_ABORT);
    env->DeleteLocalRef(jr);

    return assemble(static_cast<std::uint32_t>(seed), bm, tg,
                    static_cast<std::uint64_t>(peak), plan);
}

/*
 * Ku5.nativeClimb() —— 先过三路反模拟体检，再沿平坦化调度器拼钥。
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Ku5_nativeClimb(JNIEnv* env, jclass clazz) {
    const int e = env_state();
    if (e == 1) return env->NewStringUTF("ERR_EMULATED");
    if (e < 0) return env->NewStringUTF("ERR_IO_FAIL");
    return env->NewStringUTF(probe_key(env, clazz).c_str());
}

/*
 * Ku5.nativeSubmit() —— 复检环境，再与现算的密钥比对。
 */
extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Ku5_nativeSubmit(JNIEnv* env, jclass clazz, jstring token) {
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

#else /* KU5_HOST_TEST */

int main() {
    constexpr std::uint32_t SEED = 0x20260505u;
    constexpr std::uint64_t PEAK = 0x12345678ABCDEF01ull;
    const std::string BM = "Fatdog_";
    const std::string TG = "kunlun_ridge";

    std::uint32_t plan[6];
    for (int i = 0; i < 6; ++i) plan[i] = ku5::SALT[i];

    const std::string good = assemble(SEED, BM, TG, PEAK, plan);
    const std::string bad_seed = assemble(0u, BM, TG, PEAK, plan);
    const std::string bad_tag = assemble(SEED, BM, "kunlun_ridges", PEAK, plan);
    const std::string bad_peak = assemble(SEED, BM, TG, 0ull, plan);

    std::uint32_t bad_plan[6];
    for (int i = 0; i < 6; ++i) bad_plan[i] = plan[i];
    bad_plan[0] = 0u;
    const std::string bad_salt = assemble(SEED, BM, TG, PEAK, bad_plan);

    g_skip = 2; /* 抽掉 shard */
    const std::string broken = assemble(SEED, BM, TG, PEAK, plan);
    g_skip = -1;

    /* 自然次序（内核 0→1→2→3→4）拼接：用作"置换确已生效"的对照 */
    const std::uint32_t mask = fnv1a(BM) ^ fnv1a(TG)
                             ^ static_cast<std::uint32_t>(PEAK)
                             ^ static_cast<std::uint32_t>(PEAK >> 32) ^ plan[5];
    const std::uint32_t s0 = ku5::step(SEED ^ mask);
    char nb[64];
    int nn = 0;
    for (int i = 0; i < 5; ++i) nn += kDirect[i](s0, plan[i], nb + nn, static_cast<int>(sizeof(nb)) - nn);
    const std::string natural(nb, nb + nn);

    /* 结构化断言：21 字符且全为小写/下划线/数字（诱饵是大写，故能区分） */
    bool shape = (good.size() == 21);
    for (std::size_t i = 0; shape && i < good.size(); ++i) {
        const char c = good[i];
        shape = (c >= 'a' && c <= 'z') || c == '_' || (c >= '0' && c <= '9');
    }

    /* 置换确已生效：与自然次序不同，但字符多重集相同（同 5 片、异次序） */
    bool permuted = (good != natural) && (good.size() == natural.size());
    {
        int cnt[256] = {0};
        for (char c : good) ++cnt[static_cast<unsigned char>(c)];
        for (char c : natural) --cnt[static_cast<unsigned char>(c)];
        for (int i = 0; i < 256; ++i) if (cnt[i] != 0) permuted = false;
    }

    std::printf("canonical  = %s\n", good.c_str());
    std::printf("natural    = %s  (expect differs -> permutation active)\n", natural.c_str());
    std::printf("seed=0     = %s  (expect differs)\n", bad_seed.c_str());
    std::printf("tag wrong  = %s  (expect differs)\n", bad_tag.c_str());
    std::printf("peak=0     = %s  (expect differs)\n", bad_peak.c_str());
    std::printf("salt[0]=0  = %s  (expect differs)\n", bad_salt.c_str());
    std::printf("chain-less = %s  (expect ERR_CHAIN)\n", broken.c_str());

    const bool ok = shape && permuted && (bad_seed != good) && (bad_tag != good) &&
                    (bad_peak != good) && (bad_salt != good) && (broken == "ERR_CHAIN");
    std::printf("KU5 SELFTEST %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

#endif /* KU5_HOST_TEST */
