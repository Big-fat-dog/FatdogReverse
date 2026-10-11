/*
 * 昆仑山 KL3 渡鸦桥 —— 六 so 接力链的公共约定（手写，勿由生成器覆盖）。
 *
 * 链形： acorn(门面) --dlsym--> bramble -> cinder -> drift -> elder -> fable
 *        五枚内核各贡献 1 个字符拼出尾段；缺任一内核 → 断链 ERR_CHAIN。
 *
 * 状态： 每枚内核把传入状态做一次 LCG 步进，用高位 & 0x1F 选表取自己的片段；
 *        状态初值来自 Java 的 Ku3.bridgeSeed()（int 回调），
 *        前段明文来自 Ku3.halfA()（String 回调）——两处都必须补。
 *
 * 设计口径：片段真值只落在小写字母位；31 格诱饵取大写字母/数字，
 *          与小写真值绝不撞车（选错状态 → 尾段全是大写/数字，一眼假）。
 */
#ifndef KUNLUN_CHAIN_H
#define KUNLUN_CHAIN_H

#include <cstddef>
#include <cstdint>
#include <array>

namespace ku3 {

/* glibc 同参线性同余：单步演进对 unidbg trace 一目了然 */
constexpr std::uint32_t LCG_MUL = 1103515245u;
constexpr std::uint32_t LCG_ADD = 12345u;

[[nodiscard]] constexpr std::uint32_t step(std::uint32_t s) noexcept {
    return s * LCG_MUL + LCG_ADD;
}

/* 取状态高 6 位做表索引 */
[[nodiscard]] constexpr std::uint32_t sel(std::uint32_t s) noexcept {
    return (s >> 16) & 0x1Fu;
}

/* 片段表：tag 便于逆向时对号入座，cells 是 32 格选择池 */
struct Table {
    const char* tag;
    std::array<char, 32> cells;
};

/*
 * 编译期造表：诱饵按 (i*7+3) mod |pool| 铺满，真值只覆盖 idx 那一格。
 * 模板形参 P 由字面量池自动推导（sizeof 含结尾 NUL，故取 P-1）。
 */
template <std::size_t P>
[[nodiscard]] constexpr Table make_table(const char* tag, unsigned idx, char real,
                                         const char (&pool)[P]) noexcept {
    Table t{tag, {}};
    for (unsigned i = 0; i < 32; ++i) {
        t.cells[i] = pool[(i * 7u + 3u) % (P - 1u)];
    }
    t.cells[idx % 32u] = real;
    return t;
}

/* 内核统一动作：步进一次、回吐新状态、返回本片字符 */
[[nodiscard]] inline int pick(const Table& t, std::uint32_t state, std::uint32_t* out) noexcept {
    const std::uint32_t s = step(state);
    if (out) *out = s;
    return static_cast<int>(static_cast<unsigned char>(t.cells[sel(s)]));
}

} // namespace ku3

/* 默认可见性：内核的 ku3_ry_* 才能被门面 dlsym 摘到 */
#define KU3_VIS extern "C" __attribute__((visibility("default")))

#endif /* KUNLUN_CHAIN_H */
