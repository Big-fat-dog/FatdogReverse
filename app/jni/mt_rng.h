/*
 * mt_rng.h — 忠实复刻 CPython random.Random 的 MT19937（C++ 可移植版）
 *
 * 用途：KL36-KL40 的 nativeAnswer() 现在从该关卡「与服务端相同的整数 SEED」
 *       现场复算 1000 个 randint(1,100) 之和，再交给各文件自带的 sha256 取前 8 位，
 *       而不再硬编码 sum 字面量。这样将来服务端改 SEED 时 native 会自动跟着变。
 *
 * 语义严格对齐 CPython 3.x（_randommodule.c + random.py）：
 *   - version-2 整型 seed -> 小端字节 -> init_by_array
 *   - genrand_uint32（标准 MT19937 扭转）
 *   - getrandbits(k)：生成 ceil(k/32) 个字，高位在前，保留最高 k 位
 *   - _randbelow(n)：k=n.bit_length()，对 getrandbits(k) 做拒绝采样
 *   - randint(a,b) = a + _randbelow(b-a+1)
 *
 * 已用 Python 3.13 ground-truth 逐位验证：
 *   seed=20271125 -> 49495, 20280615 -> 49958, 20280701 -> 50778,
 *   20280715 -> 49978, 20280720 -> 52005。
 */
#ifndef FATDOG_MT_RNG_H
#define FATDOG_MT_RNG_H

#include <cstdint>
#include <cstddef>

namespace mt_rng {

static const int      MT_N = 624;
static const int      MT_M = 397;
static const uint32_t MT_MATRIX_A   = 0x9908B0DFUL;
static const uint32_t MT_UPPER_MASK = 0x80000000UL;
static const uint32_t MT_LOWER_MASK = 0x7FFFFFFFUL;

static uint32_t mt_state[MT_N];
static int      mt_index = MT_N + 1;

static void mt_init_by_array(const uint32_t* key, int key_length) {
    uint32_t* state = mt_state;
    size_t i, j, k;
    state[0] = 19650218UL;
    for (i = 1; i < (size_t)MT_N; i++) {
        state[i] = (1812433253UL * (state[i - 1] ^ (state[i - 1] >> 30)) +
                    (uint32_t)i) & 0xFFFFFFFFUL;
    }
    state[0] = 19650218UL;
    i = 1; j = 0;
    k = ((size_t)MT_N > (size_t)key_length ? (size_t)MT_N : (size_t)key_length);
    for (; k; k--) {
        state[i] = (state[i] ^ ((state[i - 1] ^ (state[i - 1] >> 30)) * 1664525UL)) +
                   key[j] + (uint32_t)j;
        state[i] &= 0xFFFFFFFFUL;
        i++; j++;
        if (i >= (size_t)MT_N) { state[0] = state[MT_N - 1]; i = 1; }
        if (j >= (size_t)key_length) j = 0;
    }
    for (k = (size_t)MT_N - 1; k; k--) {
        state[i] = (state[i] ^ ((state[i - 1] ^ (state[i - 1] >> 30)) * 1566083941UL)) -
                   (uint32_t)i;
        state[i] &= 0xFFFFFFFFUL;
        i++;
        if (i >= (size_t)MT_N) { state[0] = state[MT_N - 1]; i = 1; }
    }
    state[0] = 0x80000000UL;
    mt_index = MT_N; /* 强制首调用即扭转 */
}

/* version-2 整型 seed：我们的 seed 均 < 2^32，单字即可 */
static void py_seed(uint32_t seed) {
    mt_init_by_array(&seed, 1);
}

static uint32_t mt_genrand_uint32() {
    uint32_t y;
    static const uint32_t mag01[2] = {0, MT_MATRIX_A};
    if (mt_index >= MT_N) {
        if (mt_index > MT_N) return 0; /* 不应发生 */
        for (int i = 0; i < MT_N - MT_M; i++) {
            y = (mt_state[i] & MT_UPPER_MASK) | (mt_state[i + 1] & MT_LOWER_MASK);
            mt_state[i] = mt_state[i + MT_M] ^ (y >> 1) ^ mag01[y & 1];
        }
        for (int i = MT_N - MT_M; i < MT_N - 1; i++) {
            y = (mt_state[i] & MT_UPPER_MASK) | (mt_state[i + 1] & MT_LOWER_MASK);
            mt_state[i] = mt_state[i + (MT_M - MT_N)] ^ (y >> 1) ^ mag01[y & 1];
        }
        y = (mt_state[MT_N - 1] & MT_UPPER_MASK) | (mt_state[0] & MT_LOWER_MASK);
        mt_state[MT_N - 1] = mt_state[MT_M - 1] ^ (y >> 1) ^ mag01[y & 1];
        mt_index = 0;
    }
    y = mt_state[mt_index++];
    y ^= (y >> 11);
    y ^= (y << 7)  & 0x9D2C5680UL;
    y ^= (y << 15) & 0xEFC60000UL;
    y ^= (y >> 18);
    return y;
}

static int mt_bit_length(uint32_t n) {
    int r = 0;
    while (n) { n >>= 1; r++; }
    return r;
}

/* getrandbits(k)：保留生成字流的最高 k 位（与服务端一致） */
static uint64_t mt_getrandbits(int k) {
    int words = (k + 31) / 32;
    uint64_t value = 0;
    for (int i = 0; i < words; i++) {
        value = (value << 32) | (uint64_t)mt_genrand_uint32();
    }
    value >>= (words * 32 - k);
    return value & ((k >= 64) ? ~0ULL : ((1ULL << k) - 1));
}

static uint32_t mt_randbelow(uint32_t n) {
    int k = mt_bit_length(n);
    uint64_t r = mt_getrandbits(k);
    while (r >= n) r = mt_getrandbits(k);
    return (uint32_t)r;
}

static uint32_t mt_randint(uint32_t a, uint32_t b) {
    return a + mt_randbelow(b - a + 1);
}

/*
 * 复刻 server.py 的 NUMS_KL3x 求和：
 *   random.Random(SEED) 生成 PAGES*PER_PAGE = 100*10 = 1000 个 randint(1,100)，求和。
 * 返回的 sum 再经 sha256(str(sum))[:8] 即为答案（由各关卡自带的 sha256 完成）。
 */
static uint64_t kl_server_sum(uint32_t seed, int count = 1000) {
    py_seed(seed);
    uint64_t sum = 0;
    for (int i = 0; i < count; i++) sum += mt_randint(1, 100);
    return sum;
}

} /* namespace mt_rng */

#endif /* FATDOG_MT_RNG_H */
