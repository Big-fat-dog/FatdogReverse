/*
 * 昆仑山 KL4 冰裂缝 · 内核 juniper（右分叉头，贡献第 2 片）。
 * 与 iris 同源（同一 fork 状态），仅盐不同——两支对偶是刻意设计。
 */
#include "kunlun_fork.h"

namespace {

constexpr char kSeg[] = "ier";
constexpr ku4::Table kTable = ku4::forge("juniper", kSeg, ku4::FLOW.start[1]);

} // namespace

KU4_VIS int ku4_ry_juniper(std::uint32_t state, std::uint32_t salt,
                           char* out, int cap, std::uint32_t* next) {
    return ku4::emit<sizeof(kSeg)>(kTable, state, salt, out, cap, next);
}

KU4_VIS void juniper_fold() {}
KU4_VIS void juniper_spin() {}
KU4_VIS void juniper_seal() {}
