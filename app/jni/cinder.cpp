/*
 * 昆仑山 KL3 渡鸦桥 · 内核 cinder（贡献第 2 片）。
 */
#include "kunlun_chain.h"

namespace {

constexpr char kPool[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* 第 2 片 'a'：表位 9 */
constexpr ku3::Table kTable = ku3::make_table("cinder", 9, 'a', kPool);

} // namespace

KU3_VIS int ku3_ry_cinder(std::uint32_t state, std::uint32_t* out) {
    return ku3::pick(kTable, state, out);
}

KU3_VIS void cinder_fold() {}
KU3_VIS void cinder_spin() {}
KU3_VIS void cinder_seal() {}
