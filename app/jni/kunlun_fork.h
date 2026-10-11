/*
 * 昆仑山 KL4 冰裂缝 —— 菱形分叉链的公共约定（手写，勿由生成器覆盖）。
 *
 * 形态：              gulch(门面，唯一导出 Java_ 符号者)
 *                      ├── iris   ── kindle      (左分叉：头 → 中继)
 *                      └── juniper ── larch       (右分叉：头 → 中继)
 *                            \        /            (两路同源，归并到 ↘)
 *                             → marrow (归并节点)
 *
 * 数据流：同源 fork → 两路各步进自己的盐 → 以 (左端 ^ 右端) 作为归并起点。
 *          比 KL3 的"单链接力"多出「分叉 / 归并」——读错任一支路的时序即拼错。
 *
 * 状态来源（Java 四类回调，缺一不可——比 KL3 的两类更重）：
 *   headMark()  String  → 前段明文
 *   forkSeed()  int     → fork 种子
 *   SPLIT_X     静态 int 字段 → 分叉掩码
 *   saltPlan()  int[]   → 五段盐
 *
 * 设计口径：每枚内核只在小写字母位落真值；31 格诱饵取大写字母/数字，
 *          选错状态/盐 → 该片全是大写/数字，一眼假。
 */
#ifndef KUNLUN_FORK_H
#define KUNLUN_FORK_H

#include <cstddef>
#include <cstdint>
#include <array>

namespace ku4 {

/* 与 KL3(ku3 的 glibc 同参)不同的同余参数：Numerical-Recipes LCG */
constexpr std::uint32_t A = 1664525u;
constexpr std::uint32_t C = 1013904223u;

[[nodiscard]] constexpr std::uint32_t step(std::uint32_t s) noexcept { return s * A + C; }

/* 取状态高 6 位做表基址 */
[[nodiscard]] constexpr std::uint32_t sel(std::uint32_t s) noexcept { return (s >> 16) & 0x1Fu; }

/* 片内第 j 个字符的落位：j*8 保证同片落位互不相同（32 格 / 片长 ≤ 4） */
[[nodiscard]] constexpr std::uint32_t mark(std::uint32_t s, unsigned j) noexcept {
    return (sel(s) + j * 8u) & 0x1Fu;
}

struct Table {
    const char* tag;
    std::array<char, 32> cells;
};

/* 诱饵池：大写字母 + 数字；真值（小写 / '_'）落位后覆盖 */
constexpr char POOL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* 按 片段串 + 起始状态 造表：诱饵铺满 32 格，再把片段字符落到各步落位上 */
template <std::size_t N>
[[nodiscard]] constexpr Table forge(const char* tag, const char (&seg)[N],
                                    std::uint32_t start) noexcept {
    Table t{tag, {}};
    for (unsigned i = 0; i < 32; ++i) t.cells[i] = POOL[(i * 11u + 5u) % (sizeof(POOL) - 1u)];
    std::uint32_t s = start;
    for (unsigned j = 0; j < N - 1u; ++j) {
        s = step(s);
        t.cells[mark(s, j)] = seg[j];
    }
    return t;
}

/* 规范常量：种子 / 分叉掩码 / 五段盐（saltPlan 回调）/ 五段长度（iris..marrow） */
inline constexpr std::uint32_t SEED = 0x20260404u;
inline constexpr std::uint32_t MASK = 0x5A5A5A5Au;
inline constexpr std::uint32_t SALT[5] = {0x1F3Au, 0x2E4Bu, 0x3D5Cu, 0x4C6Du, 0x5B7Eu};
inline constexpr unsigned LEN[5] = {4u, 3u, 3u, 3u, 3u};

/* 菱形数据流：fork → 左支(iris→kindle) / 右支(juniper→larch) → 归并(marrow) */
struct Flow {
    std::uint32_t start[5];
};

[[nodiscard]] constexpr Flow derive() noexcept {
    Flow r{};
    const std::uint32_t f = step(SEED ^ MASK);

    std::uint32_t a = f ^ SALT[0]; r.start[0] = a;              /* iris   起点 */
    for (unsigned j = 0; j < LEN[0]; ++j) a = step(a);          /* iris   末端 */

    std::uint32_t b = f ^ SALT[1]; r.start[1] = b;              /* juniper 起点 */
    for (unsigned j = 0; j < LEN[1]; ++j) b = step(b);          /* juniper 末端 */

    std::uint32_t c = a ^ SALT[2]; r.start[2] = c;              /* kindle 起点 */
    for (unsigned j = 0; j < LEN[2]; ++j) c = step(c);

    std::uint32_t d = b ^ SALT[3]; r.start[3] = d;              /* larch  起点 */
    for (unsigned j = 0; j < LEN[3]; ++j) d = step(d);

    r.start[4] = (a ^ b) ^ SALT[4];                             /* marrow 归并起点 */
    return r;
}

inline constexpr Flow FLOW = derive();

/* 内核统一动作：从 state^salt 起逐字符步进取表，写满本片长度 */
template <std::size_t N>
[[nodiscard]] inline int emit(const Table& t, std::uint32_t state, std::uint32_t salt,
                              char* out, int cap, std::uint32_t* next) noexcept {
    std::uint32_t s = state ^ salt;
    int n = 0;
    for (unsigned j = 0; j < N - 1u && n < cap; ++j) {
        s = step(s);
        out[n++] = t.cells[mark(s, j)];
    }
    if (next) *next = s;
    return n;
}

} // namespace ku4

/* 默认可见性：内核的 ku4_ry_* 才能被门面 dlsym 摘到 */
#define KU4_VIS extern "C" __attribute__((visibility("default")))

#endif /* KUNLUN_FORK_H */
