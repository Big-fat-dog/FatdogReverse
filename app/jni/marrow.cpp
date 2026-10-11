/*
 * 昆仑山 KL4 冰裂缝 · 内核 marrow（归并节点，贡献第 5 片）。
 * 起点 = (左支末端 ^ 右支末端) ^ 盐——两支必须都跑对，归并起点才落对。
 */
#include "kunlun_fork.h"

namespace {

constexpr char kSeg[] = "ked";
constexpr ku4::Table kTable = ku4::forge("marrow", kSeg, ku4::FLOW.start[4]);

} // namespace

KU4_VIS int ku4_ry_marrow(std::uint32_t state, std::uint32_t salt,
                          char* out, int cap, std::uint32_t* next) {
    return ku4::emit<sizeof(kSeg)>(kTable, state, salt, out, cap, next);
}

KU4_VIS void marrow_fold() {}
KU4_VIS void marrow_spin() {}
KU4_VIS void marrow_seal() {}
