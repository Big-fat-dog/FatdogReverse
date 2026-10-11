/*
 * 昆仑山 KL4 冰裂缝 · 内核 iris（左分叉头，贡献第 1 片）。
 * 自身不含 Java 回调——只做状态步进 + 片段表落位；跨 so 依赖由门面 gulch 摘取。
 */
#include "kunlun_fork.h"

namespace {

/* 本片 4 字符（小写），落位由规范状态流推导 */
constexpr char kSeg[] = "glac";
constexpr ku4::Table kTable = ku4::forge("iris", kSeg, ku4::FLOW.start[0]);

} // namespace

KU4_VIS int ku4_ry_iris(std::uint32_t state, std::uint32_t salt,
                        char* out, int cap, std::uint32_t* next) {
    return ku4::emit<sizeof(kSeg)>(kTable, state, salt, out, cap, next);
}

/* 诱饵导出：名字像内核成员，实则没有调用者 */
KU4_VIS void iris_fold() {}
KU4_VIS void iris_spin() {}
KU4_VIS void iris_seal() {}
