/*
 * Faithful reimplementation of CPython random.Random MT19937 in C.
 * Used to verify that the native KL36-KL40 answer can be derived from the
 * SAME integer SEED the server uses, instead of a hardcoded sum.
 *
 * Semantics mirrored from CPython 3.x (_randommodule.c + random.py):
 *   - version-2 int seed -> little-endian bytes -> init_by_array
 *   - genrand_uint32 (standard MT19937 twist)
 *   - getrandbits(k): generate ceil(k/32) words, MSB-first, keep top k bits
 *   - _randbelow(n): k=n.bit_length(); reject-sampling getrandbits(k)
 *   - randint(a,b) = a + _randbelow(b-a+1)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N 624
#define M 397
#define MATRIX_A   0x9908B0DFUL
#define UPPER_MASK 0x80000000UL
#define LOWER_MASK 0x7FFFFFFFUL

static uint32_t mt[N];
static int mti = N + 1;

/* ---- MT19937 core ---- */
static void init_genrand(uint32_t seed) {
    mt[0] = seed;
    for (mti = 1; mti < N; mti++) {
        mt[mti] = (1812433253UL * (mt[mti - 1] ^ (mt[mti - 1] >> 30)) +
                   (uint32_t)mti) & 0xFFFFFFFFUL;
    }
}

static void init_by_array(const uint32_t *key, int key_length) {
    uint32_t *state = mt;
    size_t i, j, k;
    state[0] = 19650218UL;
    for (i = 1; i < N; i++) {
        state[i] = (1812433253UL * (state[i - 1] ^ (state[i - 1] >> 30)) +
                    (uint32_t)i) & 0xFFFFFFFFUL;
    }
    state[0] = 19650218UL;
    i = 1; j = 0;
    k = (N > (size_t)key_length ? N : (size_t)key_length);
    for (; k; k--) {
        state[i] = (state[i] ^ ((state[i - 1] ^ (state[i - 1] >> 30)) * 1664525UL)) +
                   key[j] + (uint32_t)j;
        state[i] &= 0xFFFFFFFFUL;
        i++; j++;
        if (i >= N) { state[0] = state[N - 1]; i = 1; }
        if (j >= (size_t)key_length) j = 0;
    }
    for (k = N - 1; k; k--) {
        state[i] = (state[i] ^ ((state[i - 1] ^ (state[i - 1] >> 30)) * 1566083941UL)) -
                   (uint32_t)i;
        state[i] &= 0xFFFFFFFFUL;
        i++;
        if (i >= N) { state[0] = state[N - 1]; i = 1; }
    }
    state[0] = 0x80000000UL;
    mti = N; /* force twist on first genrand */
}

static uint32_t genrand_uint32(void) {
    uint32_t y;
    static const uint32_t mag01[2] = {0, MATRIX_A};
    if (mti >= N) {
        if (mti > N) return 0; /* should not happen */
        for (int i = 0; i < N - M; i++) {
            y = (mt[i] & UPPER_MASK) | (mt[i + 1] & LOWER_MASK);
            mt[i] = mt[i + M] ^ (y >> 1) ^ mag01[y & 1];
        }
        for (int i = N - M; i < N - 1; i++) {
            y = (mt[i] & UPPER_MASK) | (mt[i + 1] & LOWER_MASK);
            mt[i] = mt[i + (M - N)] ^ (y >> 1) ^ mag01[y & 1];
        }
        y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
        mt[N - 1] = mt[M - 1] ^ (y >> 1) ^ mag01[y & 1];
        mti = 0;
    }
    y = mt[mti++];
    y ^= (y >> 11);
    y ^= (y << 7) & 0x9D2C5680UL;
    y ^= (y << 15) & 0xEFC60000UL;
    y ^= (y >> 18);
    return y;
}

/* ---- Python layer ---- */
static int bit_length(uint32_t n) {
    int r = 0;
    while (n) { n >>= 1; r++; }
    return r;
}

/* getrandbits(k): keep the TOP k bits of the generated word stream */
static uint64_t getrandbits(int k) {
    int words = (k + 31) / 32;
    uint64_t value = 0;
    for (int i = 0; i < words; i++) {
        value = (value << 32) | (uint64_t)genrand_uint32();
    }
    value >>= (words * 32 - k);
    return value & ((k >= 64) ? ~0ULL : ((1ULL << k) - 1));
}

static uint32_t randbelow(uint32_t n) {
    int k = bit_length(n);
    uint64_t r = getrandbits(k);
    while (r >= n) r = getrandbits(k);
    return (uint32_t)r;
}

static uint32_t randint(uint32_t a, uint32_t b) {
    return a + randbelow(b - a + 1);
}

/* version-2 int seed (single 32-bit word sufficient for our seeds) */
static void py_seed(uint32_t seed) {
    init_by_array(&seed, 1);
}

/* ---- SHA-256 (minimal, self-contained, for the answer hash) ---- */
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

static uint32_t rotr(uint32_t x, int n){ return (x >> n) | (x << (32 - n)); }

static void sha256(const uint8_t *msg, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t newlen = ((len + 8) / 64 + 1) * 64;
    uint8_t *m = (uint8_t*)calloc(newlen, 1);
    memcpy(m, msg, len);
    m[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++)
        m[newlen - 1 - i] = (uint8_t)(bits >> (i * 8));
    for (size_t off = 0; off < newlen; off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)m[off+i*4]<<24)|((uint32_t)m[off+i*4+1]<<16)|
                   ((uint32_t)m[off+i*4+2]<<8)|((uint32_t)m[off+i*4+3]);
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
            uint32_t s1 = rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
            uint32_t ch = (e&f)^((~e)&g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
            uint32_t maj = (a&b)^(a&c)^(b&c);
            uint32_t t2 = S0 + maj;
            hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(h[i] >> 24);
        out[i*4+1] = (uint8_t)(h[i] >> 16);
        out[i*4+2] = (uint8_t)(h[i] >> 8);
        out[i*4+3] = (uint8_t)(h[i]);
    }
    free(m);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <seed>\n", argv[0]);
        return 1;
    }
    uint32_t seed = (uint32_t)strtoul(argv[1], NULL, 10);
    int count = (argc > 2) ? atoi(argv[2]) : 1000;

    py_seed(seed);

    uint64_t sum = 0;
    uint32_t first[10];
    for (int i = 0; i < count; i++) {
        uint32_t v = randint(1, 100);
        sum += v;
        if (i < 10) first[i] = v;
    }

    char sumstr[32];
    snprintf(sumstr, sizeof(sumstr), "%llu", (unsigned long long)sum);
    uint8_t dig[32];
    sha256((const uint8_t*)sumstr, strlen(sumstr), dig);
    char ans[9];
    static const char *hx = "0123456789abcdef";
    for (int i = 0; i < 8; i++) ans[i] = hx[(dig[i] >> 4) & 0xF], ans[i+1<8?i+1:i]=hx[dig[i]&0xF];
    ans[8] = 0;

    printf("seed=%u count=%d sum=%llu answer=%s first10=",
           seed, count, (unsigned long long)sum, ans);
    for (int i = 0; i < 10; i++) printf("%u%s", first[i], i<9?",":"\n");

    return 0;
}
