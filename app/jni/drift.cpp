/*
 * 昆仑山 KL3 渡鸦桥 · 内核 drift（贡献第 3 片）。
 */
#include "kunlun_chain.h"

namespace {

constexpr char kPool[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* 第 3 片 'v'：表位 17 */
constexpr ku3::Table kTable = ku3::make_table("drift", 17, 'v', kPool);

} // namespace

KU3_VIS int ku3_ry_drift(std::uint32_t state, std::uint32_t* out) {
    return ku3::pick(kTable, state, out);
}

KU3_VIS void drift_fold() {}
KU3_VIS void drift_spin() {}
KU3_VIS void drift_seal() {}
