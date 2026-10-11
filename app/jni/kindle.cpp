/*
 * 昆仑山 KL4 冰裂缝 · 内核 kindle（左支中继，贡献第 3 片）。
 * 起点 = 左分叉头 iris 的末端状态；这一"接力"关系只由门面运行时串起。
 */
#include "kunlun_fork.h"

namespace {

constexpr char kSeg[] = "_un";
constexpr ku4::Table kTable = ku4::forge("kindle", kSeg, ku4::FLOW.start[2]);

} // namespace

KU4_VIS int ku4_ry_kindle(std::uint32_t state, std::uint32_t salt,
                          char* out, int cap, std::uint32_t* next) {
    return ku4::emit<sizeof(kSeg)>(kTable, state, salt, out, cap, next);
}

KU4_VIS void kindle_fold() {}
KU4_VIS void kindle_spin() {}
KU4_VIS void kindle_seal() {}
