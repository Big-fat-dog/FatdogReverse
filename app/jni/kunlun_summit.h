/*
 * 昆仑山 KL5 登顶 —— 平坦化调度器（手写，勿由生成器覆盖）。
 *
 * 形态：      spire(门面，唯一导出 Java_ 符号者)
 *                ├── quarry   (片 A)
 *                ├── ridge    (片 B)
 *                ├── shard    (片 C)
 *                ├── talus    (片 D)
 *                └── verge    (片 E)
 *
 * 与 KL3（单链接力）/ KL4（菱形分叉）的本质区别：
 *   五枚内核的**执行次序不是源码里写死的**——门面把 Java 侧取来的
 *   seed / 掩码 / 六段盐揉成 s0，再用 Fisher–Yates 现算一个 5 元置换 order[]，
 *   然后以「平坦化调度器」（runtime 生成的 g_next 状态表 + switch 主分发）
 *   沿该置换依次调用内核。次序藏在运行时内存里，静态读不到；要么补全环境后
 *   直接跑出返回值，要么**trace**（Frida Stalker / unidbg trace）看它到底先调了谁。
 *
 * 状态来源（Java 五类回调，比 KL4 更多）：
 *   climbSeed()  int                    → 种子
 *   baseMark()   String                 → 掩码分量 ①
 *   SUMMIT_TAG   静态 String 字段        → 掩码分量 ②（字段读取，非方法）
 *   peakStamp()  long                   → 掩码分量 ③（64 位）
 *   routePlan()  int[]（6 段）           → 五段盐 + 掩码分量 ④
 *
 * 设计口径：每枚内核只在小写字母/下划线/数字位落真值；31 格诱饵取大写字母，
 *          状态/盐错 → 基准位错 → 该片读到的全是大写，一眼假。
 */
#ifndef KUNLUN_SUMMIT_H
#define KUNLUN_SUMMIT_H

#include <cstddef>
#include <cstdint>
#include <array>

namespace ku5 {

/* 又一条不同的同余参数（MSVC LCG）：KL3 用 glibc、KL4 用 Numerical-Recipes */
constexpr std::uint32_t A = 214013u;
constexpr std::uint32_t C = 2531011u;

[[nodiscard]] constexpr std::uint32_t step(std::uint32_t s) noexcept { return s * A + C; }

/* 取状态高 6 位做基准 */
[[nodiscard]] constexpr std::uint32_t sel(std::uint32_t s) noexcept { return (s >> 16) & 0x1Fu; }

/* 落位 = 基准 + 固定步距 j*7，同片（≤5 字）恒不撞位 */
[[nodiscard]] constexpr std::uint32_t mark(std::uint32_t base, unsigned j) noexcept {
    return (base + j * 7u) & 0x1Fu;
}

struct Table {
    const char* tag;
    std::array<char, 32> cells;
};

/* 诱饵池：全大写 + 数字（KL4 同款风格，便于"一眼假"） */
constexpr char POOL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* 按 片段串 + 基准 造表：诱饵铺满 32 格，再把片段字符落到各步落位上 */
template <std::size_t N>
[[nodiscard]] constexpr Table forge(const char* tag, const char (&seg)[N],
                                    std::uint32_t base) noexcept {
    Table t{tag, {}};
    for (unsigned i = 0; i < 32; ++i) t.cells[i] = POOL[(i * 11u + 5u) % (sizeof(POOL) - 1u)];
    for (unsigned j = 0; j < N - 1u; ++j) t.cells[mark(base, j)] = seg[j];
    return t;
}

/* 运行时置换：Fisher–Yates（order[i] = 第 i 个被访问的内核下标） */
inline void permute(std::uint32_t s0, int order[5]) noexcept {
    for (int i = 0; i < 5; ++i) order[i] = i;
    std::uint32_t s = s0;
    for (int i = 4; i > 0; --i) {
        s = step(s);
        const int j = static_cast<int>((s >> 16) % static_cast<std::uint32_t>(i + 1));
        const int t = order[i];
        order[i] = order[j];
        order[j] = t;
    }
}

/* 内核统一动作：两步混淆取基准，固定步距读表，写满本片长度 */
template <std::size_t N>
[[nodiscard]] inline int emit(const Table& t, std::uint32_t state, std::uint32_t salt,
                              char* out, int cap) noexcept {
    const std::uint32_t base = sel(step(step(state ^ salt)));
    int n = 0;
    for (unsigned j = 0; j < N - 1u && n < cap; ++j) out[n++] = t.cells[mark(base, j)];
    return n;
}

/* 规范盐（routePlan() 回调前 5 段） */
inline constexpr std::uint32_t SALT[6] = {
    0x11223344u, 0x23344556u, 0x34455667u, 0x45566778u, 0x56677889u, 0x6778899Au
};

/* 状态语义（供门面用） */
enum : std::uint32_t { S_INIT = 0u, S_K0, S_K1, S_K2, S_K3, S_K4, S_END };

} // namespace ku5

/* 默认可见性：内核的 ku5_ry_* 才能被门面 dlsym 摘到 */
#define KU5_VIS extern "C" __attribute__((visibility("default")))

#endif /* KUNLUN_SUMMIT_H */
