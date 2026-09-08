/*
 * KKL4 libkkl4 代码窗口 CRC-32 基线常量独立翻译单元。
 *
 * 常量单独放 .c：kkl4.cpp 无法在编译期看到初始值，编译器只能生成
 * "从内存加载"的代码，烘焙/重编基线不会改动被 CRC 覆盖的代码窗口，
 * 构建流程能够一次收敛。本文件由 tools/gen_kkl4_crc_baseline.py 更新。
 */
#include <stdint.h>
#include "kkl4_crc_baseline.h"

#if defined(__aarch64__)
#define KKL4_OPEN_BASELINE KKL4_CRC_OPEN_ARM64
#define KKL4_SIGN_BASELINE KKL4_CRC_SIGN_ARM64
#define KKL4_COMMIT_BASELINE KKL4_CRC_COMMIT_ARM64
#define KKL4_CHECK_BASELINE KKL4_CRC_CHECK_ARM64
#elif defined(__arm__)
#define KKL4_OPEN_BASELINE KKL4_CRC_OPEN_ARMEABI_V7A
#define KKL4_SIGN_BASELINE KKL4_CRC_SIGN_ARMEABI_V7A
#define KKL4_COMMIT_BASELINE KKL4_CRC_COMMIT_ARMEABI_V7A
#define KKL4_CHECK_BASELINE KKL4_CRC_CHECK_ARMEABI_V7A
#else
#error "unsupported ABI for KKL4 tower CRC baseline"
#endif

const uint32_t kKkl4CrcOpen = KKL4_OPEN_BASELINE;
const uint32_t kKkl4CrcSign = KKL4_SIGN_BASELINE;
const uint32_t kKkl4CrcCommit = KKL4_COMMIT_BASELINE;
const uint32_t kKkl4CrcCheck = KKL4_CHECK_BASELINE;
