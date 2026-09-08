/*
 * KL15 libshale 代码段 CRC-32 基线常量独立翻译单元。
 *
 * 单独放在 .c 里是为了让 shale.c 无法在编译期看到初始值：
 * 编译器只能生成“从内存加载”的代码，基线值本身不会进入
 * nativeGuard 起始的代码窗口，重新烘焙基线不会改变窗口字节，
 * 构建流程因此能够一次收敛。
 */
#include <stdint.h>
#include "shale_crc_baseline.h"

#if defined(__aarch64__)
#define SHALE_ABI_BASELINE KL15_SHALE_CRC_BASELINE_ARM64
#elif defined(__arm__)
#define SHALE_ABI_BASELINE KL15_SHALE_CRC_BASELINE_ARMEABI_V7A
#else
#error "unsupported ABI for KL15 shale CRC baseline"
#endif

const uint32_t kShaleCrcBaseline = SHALE_ABI_BASELINE;
