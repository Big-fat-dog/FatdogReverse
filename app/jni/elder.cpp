/*
 * 昆仑山 KL3 渡鸦桥 · 内核 elder（贡献第 4 片）。
 */
#include "kunlun_chain.h"

namespace {

constexpr char kPool[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* 第 4 片 'e'：表位 27 */
constexpr ku3::Table kTable = ku3::make_table("elder", 27, 'e', kPool);

} // namespace

KU3_VIS int ku3_ry_elder(std::uint32_t state, std::uint32_t* out) {
    return ku3::pick(kTable, state, out);
}

KU3_VIS void elder_fold() {}
KU3_VIS void elder_spin() {}
KU3_VIS void elder_seal() {}
