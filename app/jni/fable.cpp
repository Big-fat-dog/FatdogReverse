/*
 * 昆仑山 KL3 渡鸦桥 · 内核 fable（链尾，贡献第 5 片）。
 *
 * 链尾之后不再有内核——它的下一个状态无人消费，仅作回传以保持接口一致。
 */
#include "kunlun_chain.h"

namespace {

constexpr char kPool[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* 第 5 片 'n'：表位 21 */
constexpr ku3::Table kTable = ku3::make_table("fable", 21, 'n', kPool);

} // namespace

KU3_VIS int ku3_ry_fable(std::uint32_t state, std::uint32_t* out) {
    return ku3::pick(kTable, state, out);
}

KU3_VIS void fable_fold() {}
KU3_VIS void fable_spin() {}
KU3_VIS void fable_seal() {}
