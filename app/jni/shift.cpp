/*
 * 天地秘境·迷阵 KL53：移形换位——字符串加密（C++ OOP 重构版）。
 *
 * 考点：OLLVM「字符串加密」(String Encryption) + C++ 面向对象藏算法。
 *  ① 关键字符串（标记 / AES 钥 / IV）不落盘明文，而是以 XOR 字节块存放，
 *     运行时三阶段解密 —— 对应 OLLVM 商业混淆（Armariris/Hikari）的三代字符串加密：
 *       变体① 古典 datadiv_decode：导出特征函数，constructor 里解密（进 .init_array）；
 *       变体② 隐藏名：解密函数名伪装成 C++ mangling，仍在 .init_array 执行；
 *       变体③ 运行时：解密推迟到 JNI_OnLoad，密钥来自其它数据。
 *     本版把三个解密例程都改写成 switch(state) 平坦化形态 —— 不再是「一眼看穿的
 *     for 循环 XOR」，静态分析要逐 case 还原才能拿到明文。
 *  ② 加密算法藏进虚函数类层次：
 *       Sigil（抽象基类）→ ShiftSigil（真身 AES-128-CBC）/ SwapSigil / DriftSigil（诱饵）
 *       Tally（抽象基类）→ ShiftTally（真身 MD5）/ SwapTally（诱饵）
 *     调用点只有基类指针 + 虚派发（LDR X8,[X0]; LDR X9,[X8,#N]; BLR X9），
 *     需恢复 vtable 才能定位真派生类。RTTI 保留类名作线索（.rodata 的 _ZTI*）。
 *  ③ AES 轮函数本身被「轻度平坦化」：addkey/sub/shift/mix 分散进 switch 状态机。
 *  ④ 密钥不以明文数组出现：Base64 串经 XOR 字符串加密，类构造函数内解码装填，
 *     析构函数 secure_zero —— hook 析构可反推密钥长度。
 *  ⑤ JNI_OnLoad 整体套 switch 分发器 + 不透明谓词（后三关要求）。
 *
 * 算法（迷阵第三关，MD5 签名；语义与 C 版逐字节一致）：
 *   enc  = hex(AES-128-CBC(aes_key, iv, "page=N&ts=T" PKCS5))
 *   sign = MD5("Fatdog_shift|" + page + "|" + ts)
 *   aes_key = SHA256("Fatdog_shift|aes")[:16]，iv = SHA256("Fatdog_shift|iv")[:16]
 *   标记 + 密钥 Base64 串均经 XOR 字符串加密，strings 看不到明文。
 *
 * 破解路线：
 *   ① strings / 导出表找 datadiv_decode 特征 → hook 拿解密后明文
 *   ② unicorn / AndroidNativeEmu 模拟执行 .init_array 段，dump 解密后的 .data
 *   ③ Frida 在 JNI_OnLoad 后 dump 内存明文（或 hook 三个解密例程）
 *   ④ 恢复 ShiftSigil / ShiftTally 的 vtable，排掉 Swap / Drift 诱饵
 *   ⑤ Python 复刻 AES-CBC + MD5 取数
 *
 * 标记（真）：Fatdog_shift  — 经字符串加密（XOR 0x5A），运行时解密。
 * 诱饵（假）：Fatdog_swap   — 一字之差陷阱（shift→swap）。
 */
#include <jni.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ==================== 不透明谓词（.bss，初始 0） ==================== */
static volatile int g_op1 = 0;
static volatile int g_op2 = 0;
static volatile int g_op3 = 0;

/* ==================== 字符串加密：标记（XOR 0x5A） ==================== */
/* 变体一：古典 datadiv_decode。密文字节块，constructor 解密写回。 */
static unsigned char g_mark_enc[12] = {
    28, 59, 46, 62, 53, 61, 5, 41, 50, 51, 60, 46
};
#define MARK_LEN 12
static unsigned char g_mark[12];
static volatile int g_mark_ready = 0;
static volatile uint32_t g_marker_proof = 0;

/* ==================== 字符串加密：AES 钥 Base64（XOR 0x3C） ==================== */
/* 变体二：隐藏名解密函数（std__string___4921… 风格），init_array 执行。 */
static unsigned char g_aes_b64_enc[24] = {
    118, 9, 81, 82, 125, 69, 106, 68, 112, 126, 83, 101,
    82, 119, 80, 78, 125, 88, 76, 102, 125, 75, 1, 1
};
#define AES_B64_LEN 24
static char g_aes_b64[25];
static volatile int g_aes_ready = 0;

/* ==================== 字符串加密：IV Base64（XOR 0x69） ==================== */
/* 变体三：JNI_OnLoad 运行时解密。 */
static unsigned char g_iv_b64_enc[24] = {
    24, 80, 4, 95, 32, 26, 8, 10, 94, 57, 24, 40,
    8, 12, 34, 38, 80, 25, 66, 56, 4, 14, 84, 84
};
#define IV_B64_LEN 24
static char g_iv_b64[25];
static volatile int g_iv_ready = 0;

/* ==================== Base64 解码 ==================== */
static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char *in, int in_len, unsigned char *out) {
    int i, j = 0, val = 0, bits = 0;
    for (i = 0; i < in_len; i++) {
        int v = b64_val(in[i]);
        if (v < 0) continue;
        val = (val << 6) | v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out[j++] = (unsigned char)((val >> bits) & 0xFF); }
    }
    return j;
}

/* ==================== 密钥 ==================== */
static unsigned char g_mix_seed[16];
static unsigned char g_iv[16];

/* ==================== 变体②：隐藏名解密函数（平坦化） ==================== */
/* 名字刻意混淆成 C++ mangling 风格，但仍是 init_array 段执行的普通函数。 */
static void std__string___4921590060622252445(void) {
    int st = 0, i = 0;
    for (;;) {
        switch (st) {
        case 0: i = 0; st = 1; break;
        case 1: st = (i >= AES_B64_LEN) ? 3 : 2; break;
        case 2: g_aes_b64[i] = (char)(g_aes_b64_enc[i] ^ 0x3C); i++; st = 1; break;
        case 3: g_aes_b64[AES_B64_LEN] = '\0'; g_aes_ready = 1; st = 4; break;
        case 4: return;
        default: st = 4; break;
        }
    }
}

/* ==================== 变体①：datadiv_decode 特征函数（平坦化，constructor 执行） ==================== */
static void datadiv_decode1234567890(void) {
    int st = 0, i = 0;
    for (;;) {
        switch (st) {
        case 0: i = 0; st = 1; break;
        case 1: st = (i >= MARK_LEN) ? 3 : 2; break;
        case 2: g_mark[i] = (unsigned char)(g_mark_enc[i] ^ 0x5A); i++; st = 1; break;
        case 3:
            g_mark_ready = 1;
            /* 顺带解 AES 钥（变体②的函数名是"隐藏"的，这里两个都触发） */
            std__string___4921590060622252445();
            st = 4; break;
        case 4: return;
        default: st = 4; break;
        }
    }
}

/* constructor：进 .init_array 段（OLLVM 字符串解密的经典藏身处） */
__attribute__((constructor)) static void _init_strings(void) {
    datadiv_decode1234567890();
}

/* ==================== 变体③：JNI_OnLoad 运行时解密 IV（平坦化） ==================== */
static void decrypt_iv_runtime(void) {
    int st = 0, i = 0;
    for (;;) {
        switch (st) {
        case 0: i = 0; st = 1; break;
        case 1: st = (i >= IV_B64_LEN) ? 3 : 2; break;
        case 2: g_iv_b64[i] = (char)(g_iv_b64_enc[i] ^ 0x69); i++; st = 1; break;
        case 3: g_iv_b64[IV_B64_LEN] = '\0'; g_iv_ready = 1; st = 4; break;
        case 4: return;
        default: st = 4; break;
        }
    }
}

static void derive_marks(void) {
    if (!g_mark_ready) datadiv_decode1234567890();
    if (!g_aes_ready) std__string___4921590060622252445();
    if (!g_iv_ready) decrypt_iv_runtime();
    b64_decode(g_aes_b64, AES_B64_LEN, g_mix_seed);
    b64_decode(g_iv_b64, IV_B64_LEN, g_iv);
}

/* ==================== MD5 ==================== */
static uint32_t md5_rotl(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

static void md5_transform(uint32_t state[4], const unsigned char block[64]) {
    static const uint32_t K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
    };
    static const int S[64] = {
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5,9,14,20, 5,9,14,20, 5,9,14,20, 5,9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
    };
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t M[16];
    int i;
    for (i = 0; i < 16; i++)
        M[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1]<<8)
             | ((uint32_t)block[i*4+2]<<16) | ((uint32_t)block[i*4+3]<<24);
    for (i = 0; i < 64; i++) {
        uint32_t F;
        int g;
        if (i < 16) { F = (b & c) | ((~b) & d); g = i; }
        else if (i < 32) { F = (d & b) | ((~d) & c); g = (5*i + 1) % 16; }
        else if (i < 48) { F = b ^ c ^ d; g = (3*i + 5) % 16; }
        else { F = c ^ (b | (~d)); g = (7*i) % 16; }
        F = F + a + K[i] + M[g];
        a = d; d = c; c = b;
        b = b + md5_rotl(F, S[i]);
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static void md5(const unsigned char *msg, unsigned int len, unsigned char out[16]) {
    uint32_t state[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    unsigned char buf[128];
    unsigned int i, rem = len % 64;
    uint64_t bits = (uint64_t)len * 8ULL;
    for (i = 0; i < len / 64; i++)
        md5_transform(state, msg + i * 64);
    memset(buf, 0, sizeof(buf));
    memcpy(buf, msg + (len / 64) * 64, rem);
    buf[rem] = 0x80;
    if (rem >= 56) {
        md5_transform(state, buf);
        memset(buf, 0, 64);
    }
    for (i = 0; i < 8; i++)
        buf[56 + i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    md5_transform(state, buf);
    for (i = 0; i < 4; i++) {
        out[i*4]   = (unsigned char)(state[i] & 0xFF);
        out[i*4+1] = (unsigned char)((state[i] >> 8) & 0xFF);
        out[i*4+2] = (unsigned char)((state[i] >> 16) & 0xFF);
        out[i*4+3] = (unsigned char)((state[i] >> 24) & 0xFF);
    }
}

/* ==================== AES-128 常量（保留明文指纹：认算法靠它） ==================== */
static const unsigned char SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const unsigned char RCON[10] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

/* ---- AES 轮函数原子操作（rk 通过参数传入） ---- */
static void aes_sub(unsigned char s[16]) {
    int i; for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
}
static void aes_shift(unsigned char s[16]) {
    unsigned char t;
    t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
    t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
    t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
}
static unsigned char xtime(unsigned char x) {
    return (unsigned char)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}
static void aes_mix(unsigned char s[16]) {
    int c;
    for (c = 0; c < 4; c++) {
        int i = c * 4;
        unsigned char a0=s[i], a1=s[i+1], a2=s[i+2], a3=s[i+3];
        unsigned char x = a0 ^ a1 ^ a2 ^ a3;
        s[i]   ^= x ^ xtime(a0^a1);
        s[i+1] ^= x ^ xtime(a1^a2);
        s[i+2] ^= x ^ xtime(a2^a3);
        s[i+3] ^= x ^ xtime(a3^a0);
    }
}
static void round_tweak(unsigned char s[16], const unsigned char *rk, int round) {
    int i; for (i = 0; i < 16; i++) s[i] ^= rk[round*16+i];
}

/* ==================== AES 轮函数「轻度平坦化」 ==================== */
/*
 * aes_block_flat：原本顺序执行的 10 轮被改写成 switch(st) 状态机，
 * 每个轮步骤（addkey/sub/shift/mix）自成一个 case —— 与主分发器同构。
 * 语义与顺序版本逐字节一致：addkey(0); 9×(sub,shift,mix,addkey(r)); sub,shift,addkey(10)。
 */
static void aes_block_flat(unsigned char out[16], const unsigned char in[16],
                           const unsigned char *rk) {
    unsigned char s[16];
    int r = 0;
    int st = 0;
    memcpy(s, in, 16);
    for (;;) {
        switch (st) {
        case 0: round_tweak(s, rk, 0); r = 1; st = 1; break;
        case 1: aes_sub(s);   st = 2; break;
        case 2: aes_shift(s); st = 3; break;
        case 3: aes_mix(s);   st = 4; break;
        case 4: round_tweak(s, rk, r); r++; st = (r <= 9) ? 1 : 5; break;
        case 5: aes_sub(s);   st = 6; break;
        case 6: aes_shift(s); st = 7; break;
        case 7: round_tweak(s, rk, 10); st = 8; break;
        case 8: memcpy(out, s, 16); st = 9; break;
        case 9: return;
        default: st = 0; break;
        }
    }
}

/* AES-128-CBC 加密（PKCS5 填充，输出 full+16 字节） */
static void aes_cbc_enc_flat(const unsigned char *iv, const unsigned char *rk,
                             const unsigned char *plain, unsigned int len,
                             unsigned char *sigil) {
    unsigned char prev[16], block[16];
    unsigned int i, j, full;
    memcpy(prev, iv, 16);
    full = len / 16 * 16;
    for (i = 0; i < full; i += 16) {
        for (j = 0; j < 16; j++) block[j] = plain[i+j] ^ prev[j];
        aes_block_flat(sigil + i, block, rk);
        memcpy(prev, sigil + i, 16);
    }
    {
        unsigned char pad = (unsigned char)(16 - (len - full));
        unsigned char last[16];
        for (j = full; j < len; j++) last[j - full] = plain[j];
        for (j = len - full; j < 16; j++) last[j] = pad;
        for (j = 0; j < 16; j++) block[j] = last[j] ^ prev[j];
        aes_block_flat(sigil + full, block, rk);
    }
}

/* ==================== 面向对象：密钥容器 + 虚函数藏算法 ==================== */
/*
 * Sigil：抽象密文容器。子类构造函数里展开/装填密钥，析构 secure_zero ——
 * hook 析构函数即可反推密钥长度（16 字节）。
 */
class Sigil {
public:
    Sigil() : ready_(false) { memset(key_, 0, 16); memset(iv_, 0, 16); }
    virtual ~Sigil() { wipe(); }
    virtual const char *sigil() const = 0;                                  /* vtable 槽 1 */
    virtual void encrypt(const unsigned char *in, size_t n, unsigned char *out) const = 0; /* 槽 2 */
    bool ready() const { return ready_; }
protected:
    void install(const unsigned char *k, size_t klen,
                 const unsigned char *iv, size_t ivlen) {
        size_t i;
        for (i = 0; i < 16; i++) {
            key_[i] = (i < klen)  ? k[i]  : 0;
            iv_[i]  = (i < ivlen) ? iv[i] : 0;
        }
        ready_ = true;
    }
    void wipe() { size_t i; for (i = 0; i < 16; i++) { key_[i] = 0; iv_[i] = 0; } }
    unsigned char key_[16];
    unsigned char iv_[16];
    bool ready_;
};

/* 真身：AES-128-CBC + PKCS5。轮密钥只在构造函数里展开，静态看不见。 */
class ShiftSigil : public Sigil {
public:
    void load(const unsigned char *k, const unsigned char *iv) {
        install(k, 16, iv, 16); expand();
    }
    const char *sigil() const override { return "shift"; }
    void encrypt(const unsigned char *in, size_t n, unsigned char *out) const override {
        aes_cbc_enc_flat(iv_, rk_, in, (unsigned int)n, out);
    }
private:
    void expand() {
        unsigned char temp[4];
        int i, j;
        for (i = 0; i < 4; i++)
            for (j = 0; j < 4; j++) rk_[i*4+j] = key_[i*4+j];
        for (i = 4; i < 44; i++) {
            temp[0] = rk_[(i-1)*4+0];
            temp[1] = rk_[(i-1)*4+1];
            temp[2] = rk_[(i-1)*4+2];
            temp[3] = rk_[(i-1)*4+3];
            if (i % 4 == 0) {
                unsigned char t = temp[0];
                temp[0] = SBOX[temp[1]] ^ RCON[i/4-1];
                temp[1] = SBOX[temp[2]];
                temp[2] = SBOX[temp[3]];
                temp[3] = SBOX[t];
            }
            for (j = 0; j < 4; j++)
                rk_[i*4+j] = rk_[(i-4)*4+j] ^ temp[j];
        }
    }
    unsigned char rk_[176];
};

/* 诱饵①：AES-ECB（块模式错——忽略 IV，永远拿不到服务端可验的密文） */
class SwapSigil : public Sigil {
public:
    void load(const unsigned char *k, const unsigned char *iv) {
        install(k, 16, iv, 16); expand();
    }
    const char *sigil() const override { return "swap"; }
    void encrypt(const unsigned char *in, size_t n, unsigned char *out) const override {
        size_t off;
        for (off = 0; off + 16 <= n; off += 16)
            aes_block_flat(out + off, in + off, rk_);
    }
private:
    void expand() {
        unsigned char temp[4];
        int i, j;
        for (i = 0; i < 4; i++)
            for (j = 0; j < 4; j++) rk_[i*4+j] = key_[i*4+j];
        for (i = 4; i < 44; i++) {
            temp[0] = rk_[(i-1)*4+0]; temp[1] = rk_[(i-1)*4+1];
            temp[2] = rk_[(i-1)*4+2]; temp[3] = rk_[(i-1)*4+3];
            if (i % 4 == 0) {
                unsigned char t = temp[0];
                temp[0] = SBOX[temp[1]] ^ RCON[i/4-1];
                temp[1] = SBOX[temp[2]];
                temp[2] = SBOX[temp[3]];
                temp[3] = SBOX[t];
            }
            for (j = 0; j < 4; j++)
                rk_[i*4+j] = rk_[(i-4)*4+j] ^ temp[j];
        }
    }
    unsigned char rk_[176];
};

/* 诱饵②：CBC 但 IV 恒为 0（IV 错——结构性相似、结果不同） */
class DriftSigil : public Sigil {
public:
    void load(const unsigned char *k, const unsigned char *iv) {
        install(k, 16, iv, 16); expand();
    }
    const char *sigil() const override { return "drift"; }
    void encrypt(const unsigned char *in, size_t n, unsigned char *out) const override {
        unsigned char zero[16];
        memset(zero, 0, 16);
        aes_cbc_enc_flat(zero, rk_, in, (unsigned int)n, out);
    }
private:
    void expand() {
        unsigned char temp[4];
        int i, j;
        for (i = 0; i < 4; i++)
            for (j = 0; j < 4; j++) rk_[i*4+j] = key_[i*4+j];
        for (i = 4; i < 44; i++) {
            temp[0] = rk_[(i-1)*4+0]; temp[1] = rk_[(i-1)*4+1];
            temp[2] = rk_[(i-1)*4+2]; temp[3] = rk_[(i-1)*4+3];
            if (i % 4 == 0) {
                unsigned char t = temp[0];
                temp[0] = SBOX[temp[1]] ^ RCON[i/4-1];
                temp[1] = SBOX[temp[2]];
                temp[2] = SBOX[temp[3]];
                temp[3] = SBOX[t];
            }
            for (j = 0; j < 4; j++)
                rk_[i*4+j] = rk_[(i-4)*4+j] ^ temp[j];
        }
    }
    unsigned char rk_[176];
};

/* Tally：抽象摘要容器 */
class Tally {
public:
    virtual ~Tally() {}
    virtual const char *sigil() const = 0;
    virtual void compute(const unsigned char *m, size_t n, unsigned char out[16]) const = 0;
};

/* 真身：MD5 */
class ShiftTally : public Tally {
public:
    const char *sigil() const override { return "shift"; }
    void compute(const unsigned char *m, size_t n, unsigned char out[16]) const override {
        md5(m, (unsigned int)n, out);
    }
};

/* 诱饵：输入字节循环错位后再 MD5（结构相似，结果错） */
class SwapTally : public Tally {
public:
    const char *sigil() const override { return "swap"; }
    void compute(const unsigned char *m, size_t n, unsigned char out[16]) const override {
        unsigned char buf[128];
        size_t i;
        if (n > sizeof(buf)) n = sizeof(buf);
        for (i = 0; i < n; i++) buf[i] = m[(i + 1) % n];
        md5(buf, (unsigned int)n, out);
    }
};

/* ==================== 输出缓冲 ==================== */
struct Board {
    char sign_hex[33];
    char enc_hex[65];
    char msg[64];
    unsigned char enc[32];
    Sigil *sigil;
    Tally *tally;
    bool inited;
};
static Board &board() { static Board b; return b; }

/* ==================== 签名函数（虚派发 + 平坦化片段） ==================== */
static void shift_sign(int page, long long ts) {
    Board &B = board();
    static const char *H = "0123456789abcdef";
    int i, mlen;
    unsigned char dg[16];
    char sign_msg[80];

    if (!g_mark_ready || !g_aes_ready || !g_iv_ready) derive_marks();

    /* 懒建单例：构造函数内展开密钥；类层次里同时存在 2 个诱饵派生类 */
    if (!B.inited) {
        ShiftSigil *c = new ShiftSigil();
        c->load(g_mix_seed, g_iv);
        B.sigil = c;
        B.tally = new ShiftTally();
        B.inited = true;
    }
    (void)B.sigil->ready();

    /* 不透明谓词兜底（恒真；诱饵分支永不执行） */
    if (g_op1 * (g_op1 + 1) % 2 == 0 && g_op1 < 10) {
        /* enc = AES-128-CBC(aes_key, iv, "page=N&ts=T" PKCS5) —— 虚派发到 ShiftSigil */
        mlen = snprintf(B.msg, sizeof(B.msg), "page=%d&ts=%lld", page, (long long)ts);
        (void)mlen;
        B.sigil->encrypt((const unsigned char *)B.msg, (size_t)strlen(B.msg), B.enc);
        for (i = 0; i < 32; i++) {
            B.enc_hex[2*i]   = H[B.enc[i] >> 4];
            B.enc_hex[2*i+1] = H[B.enc[i] & 0xF];
        }
        B.enc_hex[64] = 0;
    } else {
        SwapSigil fake;
        fake.load(g_mix_seed, g_iv);
        fake.encrypt((const unsigned char *)B.msg, (size_t)strlen(B.msg), B.enc);
        B.enc_hex[0] = 0;
    }

    /* sign = MD5("Fatdog_shift|page|ts") —— 虚派发到 ShiftTally */
    if (g_op2 * (g_op2 + 1) % 2 == 0 && g_op2 < 10) {
        snprintf(sign_msg, sizeof(sign_msg), "Fatdog_shift|%d|%lld", page, (long long)ts);
        B.tally->compute((const unsigned char *)sign_msg, strlen(sign_msg), dg);
    } else {
        SwapTally fake;
        fake.compute((const unsigned char *)sign_msg, strlen(sign_msg), dg);
    }
    for (i = 0; i < 16; i++) {
        B.sign_hex[2*i]   = H[dg[i] >> 4];
        B.sign_hex[2*i+1] = H[dg[i] & 0xF];
    }
    B.sign_hex[32] = 0;
}

/* ==================== JNI 接口（.cpp 里必须 extern "C"） ==================== */
extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_StringGuard_nativeSign(JNIEnv *env, jclass clazz,
                                               jint page, jlong ts) {
    (void)clazz;
    shift_sign(page, (long long)ts);
    return env->NewStringUTF(board().sign_hex);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_StringGuard_nativeEnc(JNIEnv *env, jclass clazz,
                                              jint page, jlong ts) {
    (void)clazz;
    shift_sign(page, (long long)ts);
    return env->NewStringUTF(board().enc_hex);
}

/* ==================== JNI_OnLoad（整体套 switch 分发器 + 不透明谓词） ==================== */
/*
 * 后三关要求：JNI_OnLoad 不再只是纯标记壳 —— 三个字符串解密变体 + 标记留存
 * 全部拆进状态机 case，静态看不出执行顺序。
 */
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    int st = 0;
    for (;;) {
        switch (st) {
        case 0: /* 不透明谓词兜底：恒真 → 走真实链，否则跳虚假块 */
            st = (g_op3 * (g_op3 + 1) % 2 == 0 && g_op3 < 10) ? 1 : 7;
            break;
        case 1: /* 变体①：古典 datadiv_decode（constructor 已跑，这里兜底） */
            if (!g_mark_ready) datadiv_decode1234567890();
            st = 2; break;
        case 2: /* 变体②：隐藏名函数 */
            if (!g_aes_ready) std__string___4921590060622252445();
            st = 3; break;
        case 3: /* 变体③：运行时解密 IV */
            if (!g_iv_ready) decrypt_iv_runtime();
            st = 4; break;
        case 4: /* 标记留存：引用 g_mark 防止被 gc-sections 优化掉 */
            {
                uint32_t mp = 0x5A5A5A5Au;
                int i;
                for (i = 0; i < MARK_LEN; i++) mp ^= ((uint32_t)g_mark[i] << (i & 7));
                g_marker_proof = mp;
            }
            st = 6; break;
        case 6: /* 密钥派生：三变体已解密后解 base64 得 aes_key/iv —— 真机 JNI_OnLoad 后即就绪 */
            derive_marks();
            st = 5; break;
        case 5: return JNI_VERSION_1_6;
        case 7: /* 虚假块（恒不可达） */
            g_marker_proof = 0;
            return 0;
        default: st = 5; break;
        }
    }
}
