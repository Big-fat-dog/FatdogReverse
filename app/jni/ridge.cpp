/*
 * 昆仑山 KL5 登顶 · 内核 ridge（贡献一片）。
 * 自身不含 Java 回调——只做基准步进 + 片段表落位；跨 so 依赖由门面 spire 摘取。
 */
#include "kunlun_summit.h"

namespace {

constexpr char kSeg[] = "it_o";
constexpr ku5::Table kTable = ku5::forge("ridge", kSeg, 0x08u);

} // namespace

KU5_VIS int ku5_ry_ridge(std::uint32_t state, std::uint32_t salt,
                         char* out, int cap) {
    return ku5::emit<sizeof(kSeg)>(kTable, state, salt, out, cap);
}

/* 诱饵导出：名字像内核成员，实则没有调用者 */
KU5_VIS void ridge_fold() {}
KU5_VIS void ridge_spin() {}
KU5_VIS void ridge_seal() {}
