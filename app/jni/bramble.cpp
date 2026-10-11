/*
 * 昆仑山 KL3 渡鸦桥 · 内核 bramble（链首，贡献第 1 片）。
 *
 * 自身不含任何 Java 回调——它只做一次 LCG 步进 + 片段表选择。
 * 跨 so 依赖由门面 acorn 负责摘取（dlsym），故本文件独立可编。
 */
#include "kunlun_chain.h"

namespace {

/* 诱饵池：大写字母 + 数字，与真值（小写）永不同格 */
constexpr char kPool[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* 第 1 片 'r'：表位 12 由规范种子（bridgeSeed）经 LCG 推导 */
constexpr ku3::Table kTable = ku3::make_table("bramble", 12, 'r', kPool);

} // namespace

KU3_VIS int ku3_ry_bramble(std::uint32_t state, std::uint32_t* out) {
    return ku3::pick(kTable, state, out);
}

/* 诱饵导出：名字像内核成员，实则没有任何调用者 */
KU3_VIS void bramble_fold() {}
KU3_VIS void bramble_spin() {}
KU3_VIS void bramble_seal() {}
