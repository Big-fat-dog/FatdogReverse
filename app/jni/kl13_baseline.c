/*
 * KL13 CRC-32 基线常量独立翻译单元。
 *
 * 放在单独 .c 里是为了让 mantis.c 无法在编译期看到初始值：
 * 编译器只能生成“从内存加载”的代码，基线值本身不会进入
 * guard/verify_crc 的代码窗口，重新烘焙基线不会改变窗口字节，
 * 构建流程因此能够一次收敛。
 */
#include <stdint.h>
#include "kl13_crc_baseline.h"

#if defined(__aarch64__)
#define KL13_ABI_BASELINE KL13_GUARD_CRC_BASELINE_ARM64
#elif defined(__arm__)
#define KL13_ABI_BASELINE KL13_GUARD_CRC_BASELINE_ARMEABI_V7A
#else
#error "unsupported ABI for KL13 guard CRC baseline"
#endif

const uint32_t kGuardCrcBaseline = KL13_ABI_BASELINE;
