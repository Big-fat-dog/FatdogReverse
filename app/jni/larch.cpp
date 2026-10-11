/*
 * 昆仑山 KL4 冰裂缝 · 内核 larch（右支中继，贡献第 4 片）。
 * 起点 = 右分叉头 juniper 的末端状态。
 */
#include "kunlun_fork.h"

namespace {

constexpr char kSeg[] = "loc";
constexpr ku4::Table kTable = ku4::forge("larch", kSeg, ku4::FLOW.start[3]);

} // namespace

KU4_VIS int ku4_ry_larch(std::uint32_t state, std::uint32_t salt,
                         char* out, int cap, std::uint32_t* next) {
    return ku4::emit<sizeof(kSeg)>(kTable, state, salt, out, cap, next);
}

KU4_VIS void larch_fold() {}
KU4_VIS void larch_spin() {}
KU4_VIS void larch_seal() {}
