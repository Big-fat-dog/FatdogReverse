# -*- coding: utf-8 -*-
"""KKL4 锁妖塔：5 个 so 的生成器（VMP · 栈式虚拟机 + 链式解码 + AES-128-CTR + MD5）。

        ┌── libcitadel.so   JNI 门面（唯一暴露 Java_ 符号）；dlsym 其余四个内核
        ├── libobsidian.so  虚拟机内核：链式解密 + 栈式 VM 解释执行（CALL/RET 子程序）
        ├── libcavern.so    AES-128-CTR 加解密 + 十六进制编码
        ├── libtundra.so    MD5 摘要（取数签名，零 HMAC）
        └── libprowl.so     完整性守卫：调试/段权限/注入框架/模拟器/可疑映射（阈值 2）

五者缺一：门面 dlsym 拿不到内核指针 → 自检报"内核缺失"、签名返回空 → 服务端 403。

数据链（全网络取数，`GET /api/kkl4`）：
    seed(32B) = VM( 输入 = 真标记 Fatdog_dread ‖ "|kkl4_tower" )   ← 标记不进字节码
                key = seed[0:16]，iv = seed[16:32]
    enc       = hex( AES-128-CTR(key, iv, "page=N&ts=T") )
    sign      = md5( hex(seed) + enc )
服务端：AES-CTR 解 enc 必须还原出 "page=N&ts=T"，且 sign 必须对得上。

标记：真 = Fatdog_dread（UTF-16 码元藏 .data，运行时降 ASCII 喂给 VM）
      假 = Fatdog_dream（明文躺 .rodata，仅末位一字之差；派生的主钥服务端不认）

用法：
    python gen_kkl4.py                    # 生成 5 个 so 源 + 自测
    python gen_kkl4.py --selftest         # 只跑自测
"""
import hashlib
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
JNI = os.path.join(HERE, 'app', 'jni')

# ─────────────── 与 tools/gen_kkl4_vm_program.py 的共享事实（硬约束） ───────────────
MARKER = b"Fatdog_dread"
DECOY = b"Fatdog_dream"
SALT = b"|kkl4_tower"
PAGES, PER_PAGE, SEED = 100, 10, 20260923

sys.path.insert(0, os.path.join(HERE, 'tools'))
import gen_kkl4_vm_program as vmgen  # noqa: E402

assert vmgen.MARKER_REAL == MARKER and vmgen.MARKER_DECOY == DECOY and vmgen.SALT_KEY == SALT, \
    '标记/salt 与 VM 生成器不一致'
TRUE_SEED = vmgen.derive_key(MARKER, SALT, 32)

_rng = random.Random(SEED)
_NUMS = [_rng.randint(1, 100) for _ in range(PAGES * PER_PAGE)]
SUM = sum(_NUMS)
SUM_HASH = hashlib.md5(str(SUM).encode()).hexdigest()


# ─────────────────────────── 纯 Python AES-128（CTR 自测） ───────────────────────────
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11b
    return a & 0xFF


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p & 0xFF


def _expand_key(key):
    w = list(key)
    rcon = 1
    for i in range(4, 44):
        t = w[(i - 1) * 4:(i - 1) * 4 + 4]
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[x] for x in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        w += [w[(i - 4) * 4 + j] ^ t[j] for j in range(4)]
    return w


def _shift_rows(st):
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[c * 4 + r] = st[((c + r) % 4) * 4 + r]
    return out


def _mix_columns(st):
    out = [0] * 16
    m = [2, 3, 1, 1]
    for c in range(4):
        col = st[c * 4:c * 4 + 4]
        for r in range(4):
            out[c * 4 + r] = (_gmul(col[0], m[(0 - r) % 4]) ^ _gmul(col[1], m[(1 - r) % 4])
                              ^ _gmul(col[2], m[(2 - r) % 4]) ^ _gmul(col[3], m[(3 - r) % 4]))
    return out


def aes_encrypt_block(block, w):
    st = [block[i] ^ w[i] for i in range(16)]
    for rnd in range(1, 10):
        st = [SBOX[x] for x in st]
        st = _shift_rows(st)
        st = _mix_columns(st)
        st = [st[i] ^ w[rnd * 16 + i] for i in range(16)]
    st = [SBOX[x] for x in st]
    st = _shift_rows(st)
    st = [st[i] ^ w[160 + i] for i in range(16)]
    return bytes(st)


def _ctr_block(iv, j):
    base = int.from_bytes(iv[12:16], 'big')
    return iv[0:12] + ((base + j) & 0xFFFFFFFF).to_bytes(4, 'big')


def aes_ctr(key, iv, data):
    w = _expand_key(key)
    out = bytearray()
    for j, off in enumerate(range(0, len(data), 16)):
        ks = aes_encrypt_block(_ctr_block(iv, j), w)
        blk = data[off:off + 16]
        out += bytes(a ^ b for a, b in zip(blk, ks))
    return bytes(out)


# ─────────────────────────────── C++ 模板 ───────────────────────────────
def sbox_c():
    rows = []
    for i in range(0, 256, 16):
        rows.append('    ' + ', '.join('0x%02X' % b for b in SBOX[i:i + 16]) + ',')
    return 'static const uint8_t SBOX[256] = {\n' + '\n'.join(rows) + '\n};'


def marker_jchar():
    return ', '.join('0x%04X' % c for c in MARKER)


T_CITADEL = r'''/*
 * citadel —— 太玄之初 KKL4 锁妖塔的 JNI 门面。
 *
 * 本 so 是全关**唯一**导出 Java_ 符号的库；它自身不含任何算法，
 * 全部内核靠 dlsym(RTLD_DEFAULT) 从其它四个 so 取：
 *     ob_vm_seed   （obsidian）栈式虚拟机派生主钥（32B）
 *     cv_seal/cv_hex（cavern）AES-128-CTR 与十六进制
 *     td_tally/td_hex（tundra）MD5 摘要
 *     pw_scan      （prowl）  完整性守卫
 * 缺任一内核 → 自检报"内核缺失"，签名返回空串。
 *
 * 真标记以 UTF-16 码元藏在本文件的 .data（MK4[]），运行时逐字降 ASCII 后
 * 与 salt 拼成输入缓冲喂给虚拟机——标记**不进入字节码**，字节码里只有取数下标。
 */
#include <jni.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kkl4_vm_program.h"

typedef bool (*fn_vm_seed)(const uint8_t *, size_t, const uint8_t *, size_t,
                           const uint8_t *, size_t, uint8_t *, int);
typedef int  (*fn_seal)(const uint8_t *, const uint8_t *, const uint8_t *, size_t, uint8_t *);
typedef void (*fn_hex)(const uint8_t *, size_t, char *);
typedef void (*fn_tally)(const uint8_t *, size_t, uint8_t *);
typedef void (*fn_ihex)(const uint8_t *, int, char *);
typedef int  (*fn_scan)(int *);

static fn_vm_seed g_vm = NULL;
static fn_seal    g_seal = NULL;
static fn_hex     g_hex = NULL;
static fn_tally   g_tally = NULL;
static fn_ihex    g_ihex = NULL;
static fn_scan    g_scan = NULL;

static volatile int g_poisoned = 0;
static volatile int g_last_bits = 0;

/* ================= 真标记：UTF-16 藏匿（const volatile 保证不被折叠成立即数） ================= */
static const volatile jchar MK4[] = { __MARKER_JCHAR__ };
#define MK4_LEN ((int)(sizeof(MK4) / sizeof(jchar)))

/* 明文诱饵：与真标记仅末位一字之差（d/m），由 kd_seal_tag() 引用，保证进 .rodata */
static const char DECOY[] = "Fatdog_dream";
static const char SALT[]  = "|kkl4_tower";

static void bind_kernels(void) {
    if (g_vm) return;
    g_vm    = (fn_vm_seed)dlsym(RTLD_DEFAULT, "ob_vm_seed");
    g_seal  = (fn_seal)   dlsym(RTLD_DEFAULT, "cv_seal");
    g_hex   = (fn_hex)    dlsym(RTLD_DEFAULT, "cv_hex");
    g_tally = (fn_tally)  dlsym(RTLD_DEFAULT, "td_tally");
    g_ihex  = (fn_ihex)   dlsym(RTLD_DEFAULT, "td_hex");
    g_scan  = (fn_scan)   dlsym(RTLD_DEFAULT, "pw_scan");
}

static int kernel_missing(void) {
    return !(g_vm && g_seal && g_hex && g_tally && g_ihex && g_scan);
}

/* 拼装虚拟机输入缓冲：真标记(UTF-16 降 ASCII) ‖ salt。 */
static int build_input(uint8_t *in, int cap) {
    int p = 0;
    for (int i = 0; i < MK4_LEN && p < cap; i++) in[p++] = (uint8_t)(MK4[i] & 0xFF);
    for (const char *s = SALT; *s && p < cap; s++) in[p++] = (uint8_t)*s;
    return p;
}

/* 翻位投毒：让本地派生出的主钥与服务端不再一致（服务端恒 403）。 */
static void poison(uint8_t *seed) {
    if (g_poisoned) return;
    seed[7] ^= 0x40;
    g_poisoned = 1;
}

static int hit_count(int bits) {
    int h = 0;
    for (int m = 1; m != 0 && m <= 16; m <<= 1) if (bits & m) h++;
    return h;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl4Native_nativeStatus(JNIEnv *env, jclass) {
    bind_kernels();
    char buf[640];
    if (kernel_missing()) {
        snprintf(buf, sizeof(buf),
                 "内核编队不完整：虚拟机 %s / 分组 %s / 摘要 %s / 守卫 %s\n"
                 "lib/ 下五个 so 缺一不可。",
                 g_vm ? "在位" : "缺失", g_seal ? "在位" : "缺失",
                 g_tally ? "在位" : "缺失", g_scan ? "在位" : "缺失");
        return env->NewStringUTF(buf);
    }
    int bits = 0;
    g_scan(&bits);
    g_last_bits = bits;
    snprintf(buf, sizeof(buf),
             "完整性自检（命中 %d 项，>=2 触发投毒）：\n"
             "  调试器痕迹 : %s\n"
             "  可写可执行段 : %s\n"
             "  断点痕迹   : %s\n"
             "  模拟器环境 : %s\n"
             "  自映射完整性 : %s\n"
             "  主钥状态   : %s\n"
             "  明文可见   : Fatdog_dream（供比对）",
             hit_count(bits),
             (bits & 1) ? "命中" : "安全", (bits & 2) ? "命中" : "安全",
             (bits & 4) ? "命中" : "安全", (bits & 8) ? "命中" : "安全",
             (bits & 16) ? "命中" : "安全",
             g_poisoned ? "已污染（服务端将拒绝）" : "正常");
    return env->NewStringUTF(buf);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl4Native_nativeSign(JNIEnv *env, jclass, jint page, jlong ts) {
    bind_kernels();
    if (kernel_missing()) return env->NewStringUTF("");
    int bits = 0;
    g_scan(&bits);
    g_last_bits = bits;

    uint8_t in[64];
    int in_len = build_input(in, sizeof(in));

    uint8_t seed[32];
    if (!g_vm(kKkl4VmProgram, KKL4_VM_PROGRAM_BYTES,
              kKkl4VmChainSeed, KKL4_VM_CHAIN_SEED_LEN,
              in, in_len, seed, 32)) {
        g_poisoned = 1;
        return env->NewStringUTF("");
    }
    if (hit_count(bits) >= 2) poison(seed);

    char payload[64];
    int pl = snprintf(payload, sizeof(payload), "page=%d&ts=%lld", (int)page, (long long)ts);

    uint8_t ct[128];
    int cl = g_seal(seed, seed + 16, (const uint8_t *)payload, (size_t)pl, ct);
    if (cl <= 0) { g_poisoned = 1; return env->NewStringUTF(""); }
    char enc[300];
    g_hex(ct, (size_t)cl, enc);

    char kh[80];
    g_ihex(seed, 32, kh);
    char msg[420];
    snprintf(msg, sizeof(msg), "%s%s", kh, enc);
    uint8_t mac[16];
    g_tally((const uint8_t *)msg, strlen(msg), mac);
    char sign[40];
    g_ihex(mac, 16, sign);

    char out[400];
    snprintf(out, sizeof(out), "%s|%s", enc, sign);
    return env->NewStringUTF(out);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Kkl4Native_nativePoisoned(JNIEnv *env, jclass) {
    (void)env;
    return g_poisoned ? 1 : 0;
}

/* 诱饵标记的出入口：保证 DECOY 进 .rodata，同时给静态分析留一条"假线索"。 */
extern "C" __attribute__((visibility("default"))) const char *kd_seal_tag(void) {
    return DECOY;
}
'''

T_OBSIDIAN = r'''/*
 * obsidian —— 太玄之初 KKL4 锁妖塔的虚拟机内核。
 *
 * 只做一件事：把**链式（CBC 式）**加密的自定义字节码逐条解密后，用栈式解释器执行，
 * 把结果数据栈回吐给上层。真标记不在本文件、也不在字节码里——程序只含 `GETM idx`，
 * 标记字节由门面在运行时从 .data 的 UTF-16 数组喂入。
 *
 * 指令编码： word = (op << 28) | imm28
 * 链式解码： dec[n] = enc[n] ^ key[n];  key[n+1] = rotl32(key[n], 9) ^ dec[n] ^ 0x7F4A7C15
 *            （逐条依赖前一条，无法一次性整段异或解密）
 * 架构：     数据栈 + 4 通用寄存器（混合栈机）；CALL/RET 用**独立返回栈**
 * 由 tools/gen_kkl4_vm_program.py 生成对应字节码，二者必须同步修改。
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define OB_VIS __attribute__((visibility("default")))

enum {
    OB_PUSH = 0x0, OB_GETM = 0x1, OB_POPK = 0x2, OB_PUSHR = 0x3,
    OB_ADD = 0x4, OB_SUB = 0x5, OB_XOR = 0x6, OB_AND = 0x7,
    OB_MULK = 0x8, OB_ROL8 = 0x9, OB_SHL = 0xA, OB_SHR = 0xB,
    OB_CALL = 0xC, OB_RET = 0xD, OB_JZ = 0xE, OB_HALT = 0xF
};

#define OB_DSTACK 192
#define OB_RSTACK 32

static uint32_t ob_rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

/*
 * 解释执行。program 为链式密文（小端 32 位词），chain 为初始链钥（4 字节 LE），
 * in/in_len 为运行时输入缓冲（GETM 从中取字节）。
 * 返回 true 表示正常 HALT；栈内容写入 out（out_len 字节）。
 */
extern "C" OB_VIS bool ob_vm_seed(const uint8_t *program, size_t prog_len,
                                  const uint8_t *chain, size_t chain_len,
                                  const uint8_t *in, size_t in_len,
                                  uint8_t *out, int out_len) {
    if (!program || !out || out_len <= 0) return false;
    if (chain_len < 4) return false;
    size_t n = prog_len / 4;
    if (n == 0) return false;

    uint32_t *words = (uint32_t *)calloc(n, sizeof(uint32_t));
    if (!words) return false;

    uint32_t k = (uint32_t)chain[0] | ((uint32_t)chain[1] << 8)
               | ((uint32_t)chain[2] << 16) | ((uint32_t)chain[3] << 24);
    for (size_t i = 0; i < n; i++) {
        uint32_t e = (uint32_t)program[i * 4] | ((uint32_t)program[i * 4 + 1] << 8)
                   | ((uint32_t)program[i * 4 + 2] << 16) | ((uint32_t)program[i * 4 + 3] << 24);
        uint32_t d = e ^ k;
        words[i] = d;
        k = ob_rotl32(k, 9) ^ d ^ 0x7F4A7C15u;
    }

    uint32_t regs[4] = {0, 0, 0, 0};
    uint32_t st[OB_DSTACK];
    uint32_t rstack[OB_RSTACK];
    int sp = 0, rp = 0;
    int pc = 0, steps = 0;
    bool halted = false;
    while (pc >= 0 && (size_t)pc < n && steps < 200000) {
        uint32_t w = words[pc];
        uint32_t op = (w >> 28) & 0xFu, imm = w & 0x0FFFFFFFu;
        steps++;
        bool jumped = false;
        switch (op) {
        case OB_PUSH:  if (sp < OB_DSTACK) st[sp++] = imm & 0xFFFFFu; break;
        case OB_GETM: {
            uint32_t idx = imm & 0xFFu;
            uint32_t v = (in && idx < in_len) ? in[idx] : 0u;
            if (sp < OB_DSTACK) st[sp++] = v;
            break;
        }
        case OB_POPK:  if (sp > 0) regs[imm & 0xFu] = st[--sp]; break;
        case OB_PUSHR: if (sp < OB_DSTACK) st[sp++] = regs[imm & 0xFu]; break;
        case OB_ADD:   if (sp >= 2) { uint32_t b = st[--sp], a = st[--sp]; st[sp++] = a + b; } break;
        case OB_SUB:   if (sp >= 2) { uint32_t b = st[--sp], a = st[--sp]; st[sp++] = a - b; } break;
        case OB_XOR:   if (sp >= 2) { uint32_t b = st[--sp], a = st[--sp]; st[sp++] = a ^ b; } break;
        case OB_AND:   if (sp >= 2) { uint32_t b = st[--sp], a = st[--sp]; st[sp++] = a & b; } break;
        case OB_MULK:  if (sp >= 1) { st[sp - 1] = st[sp - 1] * imm; } break;
        case OB_ROL8:  if (sp >= 1) {
            uint32_t v = st[sp - 1] & 0xFFu;
            uint32_t r = imm & 7u;
            st[sp - 1] = ((v << r) | (v >> (8 - r))) & 0xFFu;
        } break;
        case OB_SHL:   if (sp >= 1) { st[sp - 1] = st[sp - 1] << (imm & 0x1Fu); } break;
        case OB_SHR:   if (sp >= 1) { st[sp - 1] = st[sp - 1] >> (imm & 0x1Fu); } break;
        case OB_CALL:  if (rp < OB_RSTACK) rstack[rp++] = (uint32_t)(pc + 1);
                       pc = (int)imm; jumped = true; break;
        case OB_RET:   if (rp > 0) { pc = (int)rstack[--rp]; jumped = true; } break;
        case OB_JZ:    if (sp >= 1) { uint32_t v = st[--sp];
                           if (v == 0) { pc = (int)imm; jumped = true; } } break;
        case OB_HALT:  halted = true; break;
        default: free(words); return false;
        }
        if (halted) break;
        if (!jumped) pc++;
    }
    bool ok = halted && sp >= out_len;
    if (ok) for (int i = 0; i < out_len; i++) out[i] = (uint8_t)(st[i] & 0xFFu);
    free(words);
    return ok;
}

/* 诱饵：另一组形状相同、值不同的"主钥"（服务端不认）。 */
extern "C" OB_VIS void ob_decoy_head(uint8_t *out, int n) {
    for (int i = 0; i < n && i < 32; i++) out[i] = (uint8_t)(0x3C ^ (i * 0x17));
}
'''

T_CAVERN = r'''/*
 * cavern —— 太玄之初 KKL4 锁妖塔的分组原语内核。
 *
 * AES-128 分组 + **CTR 模式**（计数器块 = iv[0:12] ‖ (iv[12:16] + 块号) 大端）。
 * S 盒按 FIPS-197 硬编码；轮常量 Rcon 用 xtime 现算。CTR 加解密同构。
 */
#include <stdint.h>
#include <string.h>

#define CV_VIS __attribute__((visibility("default")))

__SBOX__

static uint8_t cv_xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }

static uint8_t cv_gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        a = cv_xtime(a);
        b >>= 1;
    }
    return p;
}

static void cv_key_expand(const uint8_t key[16], uint8_t rk[176]) {
    for (int i = 0; i < 16; i++) rk[i] = key[i];
    uint8_t rcon = 1;
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        for (int j = 0; j < 4; j++) t[j] = rk[(i - 1) * 4 + j];
        if (i % 4 == 0) {
            uint8_t tmp = t[0]; t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = tmp;
            for (int j = 0; j < 4; j++) t[j] = SBOX[t[j]];
            t[0] ^= rcon;
            rcon = cv_xtime(rcon);
        }
        for (int j = 0; j < 4; j++) rk[i * 4 + j] = rk[(i - 4) * 4 + j] ^ t[j];
    }
}

static void cv_add_rk(uint8_t s[16], const uint8_t *rk) {
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
}

static void cv_sub_bytes(uint8_t s[16]) {
    for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]];
}

static void cv_shift_rows(uint8_t s[16]) {
    uint8_t t;
    t = s[1];  s[1]  = s[5];  s[5]  = s[9];  s[9]  = s[13]; s[13] = t;
    t = s[2];  s[2]  = s[10]; s[10] = t;     t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7];  s[7]  = s[3];  s[3]  = t;
}

static void cv_mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        uint8_t a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
        s[i]     = (uint8_t)(cv_gmul(a0, 2) ^ cv_gmul(a1, 3) ^ a2 ^ a3);
        s[i + 1] = (uint8_t)(a0 ^ cv_gmul(a1, 2) ^ cv_gmul(a2, 3) ^ a3);
        s[i + 2] = (uint8_t)(a0 ^ a1 ^ cv_gmul(a2, 2) ^ cv_gmul(a3, 3));
        s[i + 3] = (uint8_t)(cv_gmul(a0, 3) ^ a1 ^ a2 ^ cv_gmul(a3, 2));
    }
}

static void cv_encrypt_block(const uint8_t in[16], const uint8_t rk[176], uint8_t out[16]) {
    uint8_t s[16];
    memcpy(s, in, 16);
    cv_add_rk(s, rk);
    for (int r = 1; r < 10; r++) {
        cv_sub_bytes(s);
        cv_shift_rows(s);
        cv_mix_columns(s);
        cv_add_rk(s, rk + r * 16);
    }
    cv_sub_bytes(s);
    cv_shift_rows(s);
    cv_add_rk(s, rk + 160);
    memcpy(out, s, 16);
}

/* AES-128-CTR 加解密（同构）；返回输出长度（== 输入长度），失败 -1。 */
extern "C" CV_VIS int cv_seal(const uint8_t key[16], const uint8_t iv[16],
                              const uint8_t *in, size_t len, uint8_t *out) {
    if (!key || !iv || !in || !out) return -1;
    uint8_t rk[176];
    cv_key_expand(key, rk);
    uint32_t base = ((uint32_t)iv[12] << 24) | ((uint32_t)iv[13] << 16)
                  | ((uint32_t)iv[14] << 8) | (uint32_t)iv[15];
    for (size_t off = 0; off < len; off += 16) {
        uint8_t ctr[16], ks[16];
        memcpy(ctr, iv, 12);
        uint32_t c = base + (uint32_t)(off / 16);
        ctr[12] = (uint8_t)(c >> 24); ctr[13] = (uint8_t)(c >> 16);
        ctr[14] = (uint8_t)(c >> 8);  ctr[15] = (uint8_t)c;
        cv_encrypt_block(ctr, rk, ks);
        size_t m = (len - off < 16) ? (len - off) : 16;
        for (size_t i = 0; i < m; i++) out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
    }
    return (int)len;
}

/* 十六进制编码（小写）。 */
extern "C" CV_VIS void cv_hex(const uint8_t *in, size_t len, char *out) {
    const char *t = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = t[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = t[in[i] & 0xF];
    }
    out[len * 2] = '\0';
}
'''

T_TUNDRA = r'''/*
 * tundra —— 太玄之初 KKL4 锁妖塔的摘要内核（MD5，零 HMAC）。
 *
 * 取数签名 = md5( hex(主钥) + 密文十六进制 )，由上层拼好后交给 td_tally。
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TD_VIS __attribute__((visibility("default")))

static const uint32_t TD_K[64] = {
    0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
    0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
    0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
    0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
    0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
    0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
    0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
    0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u
};
#define TD_RL(x,c) (((x) << (c)) | ((x) >> (32 - (c))))

extern "C" TD_VIS void td_tally(const uint8_t *msg, size_t len, uint8_t out[16]) {
    uint32_t h[4] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
    size_t n = len + 1;
    size_t rem = n % 64;
    size_t pad = rem > 56 ? 120 - rem : 56 - rem;
    n += pad + 8;
    uint8_t *buf = (uint8_t *)calloc(n, 1);
    if (!buf) { memset(out, 0, 16); return; }
    memcpy(buf, msg, len);
    buf[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) buf[n - 8 + i] = (uint8_t)(bits >> (i * 8));
    for (size_t off = 0; off < n; off += 64) {
        uint32_t m[16];
        for (int i = 0; i < 16; i++)
            m[i] = ((uint32_t)buf[off + i * 4]) | ((uint32_t)buf[off + i * 4 + 1] << 8)
                 | ((uint32_t)buf[off + i * 4 + 2] << 16) | ((uint32_t)buf[off + i * 4 + 3] << 24);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        static const int S[64] = {
            7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
            5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
            4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
            6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
        };
        for (int i = 0; i < 64; i++) {
            uint32_t f; int g;
            if (i < 16)      { f = (b & c) | (~b & d);        g = i; }
            else if (i < 32) { f = (d & b) | (~d & c);        g = (5 * i + 1) % 16; }
            else if (i < 48) { f = b ^ c ^ d;                 g = (3 * i + 5) % 16; }
            else             { f = c ^ (b | ~d);              g = (7 * i) % 16; }
            uint32_t tmp = d;
            d = c; c = b;
            b = b + TD_RL(a + f + TD_K[i] + m[g], S[i]);
            a = tmp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    }
    free(buf);
    for (int i = 0; i < 4; i++) {
        out[i * 4]     = (uint8_t)h[i];
        out[i * 4 + 1] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(h[i] >> 24);
    }
}

extern "C" TD_VIS void td_hex(const uint8_t *in, int n, char *out) {
    const char *t = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[i * 2] = t[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = t[in[i] & 0xF];
    }
    out[n * 2] = '\0';
}
'''

T_PROWL = r'''/*
 * prowl —— 太玄之初 KKL4 锁妖塔的完整性守卫（评分阈值制）。
 *
 * 五路（全部只查"有没有人动过我的代码/运行环境"，**不内置任何第三方注入框架检测**，
 * 对齐太玄之初的守卫白名单 G1/G3/G4/G5，避免与扶桑树分区撞题）：
 *   ① 调试器痕迹  /proc/self/status:TracerPid
 *   ② 段权限审计  自身映射里出现可写+可执行的段
 *   ③ 断点痕迹    本函数首 4 字节是否为 BRK / INT3 编码
 *   ④ 环境检测    ro.kernel.qemu 等模拟器特征
 *   ⑤ 自映射完整性 自身 so 的可执行段被标记 `(deleted)`（文件被替换/删除后仍在内存执行）
 *
 * 返回命中位掩码；上层按"命中数 >= 2"判风险，命中即静默投毒（签名主钥翻位）。
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/system_properties.h>

#define PW_VIS __attribute__((visibility("default")))

#define HIT_TRACE   1
#define HIT_SECTION 2
#define HIT_BREAK   4
#define HIT_EMU     8
#define HIT_SELF    16

static int pw_tracer(void) {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return 0;
    char buf[4096];
    int n = (int)read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    char *p = strstr(buf, "TracerPid:");
    if (!p) return 0;
    return atoi(p + 10) != 0 ? 1 : 0;
}

/* 段权限审计：maps 行首即地址区间与权限位（如 r-xp / rw-p / rwxp）——
 * 出现 rwx = 同一段同时可写可执行，属可疑（反内存补丁）。 */
static int pw_section(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    int hit = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "rwx")) { hit = 1; break; }
    }
    fclose(f);
    return hit;
}

/* 断点检测：本函数首 4 字节若被下断点（BRK/INT3）即命中。 */
static int pw_break(void) {
    uint32_t head = 0;
    memcpy(&head, (const void *)(uintptr_t)&pw_break, 4);
    if (head == 0xD4200000u) return 1;                            /* BRK #0（AArch64） */
    if (head == 0xCCCCCCCCu || (head & 0xFF) == 0xCC) return 1;   /* INT3（x86 兼容） */
    return 0;
}

/* 自映射完整性：本关五个 so 的可执行段被标记 `(deleted)`（文件替换/删除后仍在跑）。 */
static int pw_selfmap(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    static const char *own[] = {
        "libcitadel.so", "libobsidian.so", "libcavern.so",
        "libtundra.so", "libprowl.so", 0
    };
    char line[512];
    int hit = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, " r-x") && !strstr(line, "rwx")) continue;
        if (!strstr(line, " (deleted)")) continue;
        for (int i = 0; own[i]; i++) {
            if (strstr(line, own[i])) { hit = 1; break; }
        }
        if (hit) break;
    }
    fclose(f);
    return hit;
}

static int pw_emulator(void) {
    char v[128];
    if (__system_property_get("ro.kernel.qemu", v) > 0 && v[0] == '1') return 1;
    if (__system_property_get("init.svc.qemud", v) > 0 && strcmp(v, "running") == 0) return 1;
    if (__system_property_get("ro.build.characteristics", v) > 0 && strstr(v, "emulator")) return 1;
    return 0;
}

extern "C" PW_VIS int pw_scan(int *detail) {
    int bits = 0;
    if (pw_tracer())   bits |= HIT_TRACE;
    if (pw_section())  bits |= HIT_SECTION;
    if (pw_break())    bits |= HIT_BREAK;
    if (pw_emulator()) bits |= HIT_EMU;
    if (pw_selfmap())  bits |= HIT_SELF;
    if (detail) *detail = bits;
    return bits;
}
'''


def c_header():
    return ('/* 自动生成：python gen_kkl4.py —— 请勿手改。 */\n'
            '/* 太玄之初 KKL4 锁妖塔 · 五 so 编队（门面/虚拟机/分组/摘要/守卫）。 */\n\n')


def selftest():
    ok = True
    # ① AES-128 FIPS-197 附录 B 向量
    key = bytes(range(16))
    pt = bytes.fromhex('00112233445566778899aabbccddeeff')
    w = _expand_key(key)
    ct = aes_encrypt_block(pt, w)
    print('AES  block  = %s' % ct.hex())
    print('AES  expect = 69c4e0d86a7b0430d8cdb78070b4c55a')
    if ct != bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a'):
        print('FAIL: AES 向量不符'); ok = False
    # ② CTR 往返（多长度）
    iv = bytes((0xA0 + i) & 0xFF for i in range(16))
    for n in (1, 15, 16, 17, 40, 96):
        d = bytes((i * 11 + 5) & 0xFF for i in range(n))
        if aes_ctr(key, iv, aes_ctr(key, iv, d)) != d:
            print('FAIL: CTR 往返失败 len=%d' % n); ok = False
    # ③ VM 生成器一致
    _, enc_words, _ = vmgen.encode_program(len(MARKER), len(SALT), 32)
    got = vmgen.vm_seed(enc_words, vmgen.build_input(MARKER, SALT), 32)
    print('VM     seed = %s' % got.hex())
    print('pure   seed = %s' % TRUE_SEED.hex())
    if got != TRUE_SEED:
        print('FAIL: VM 与纯函数不一致'); ok = False
    # ④ 端到端签名形状 + 服务端解密回环
    payload = b'page=7&ts=1700000000'
    enc_ct = aes_ctr(TRUE_SEED[:16], TRUE_SEED[16:], payload)
    sy = hashlib.md5(TRUE_SEED.hex().encode() + enc_ct.hex().encode()).hexdigest()
    back = aes_ctr(TRUE_SEED[:16], TRUE_SEED[16:], enc_ct)
    if back != payload:
        print('FAIL: 端到端解密回环失败'); ok = False
    print('CTR    key = %s' % TRUE_SEED[:16].hex())
    print('CTR    iv  = %s' % TRUE_SEED[16:].hex())
    print('enc sample = %s' % enc_ct.hex())
    print('sign sample= %s' % sy)
    # ⑤ MD5 已知向量
    if hashlib.md5(b'abc').hexdigest() != '900150983cd24fb0d6963f7d28e17f72':
        print('FAIL: hashlib MD5 异常'); ok = False
    print('SUM        = %d' % SUM)
    print('SUM_HASH   = %s' % SUM_HASH)
    print('SELFTEST', 'OK' if ok else 'FAILED')
    return ok


def main():
    args = sys.argv[1:]
    ok = selftest()
    if '--selftest' in args:
        sys.exit(0 if ok else 1)
    if not ok:
        sys.exit(1)

    files = {
        'citadel.cpp': T_CITADEL.replace('__MARKER_JCHAR__', marker_jchar()),
        'obsidian.cpp': T_OBSIDIAN,
        'cavern.cpp': T_CAVERN.replace('__SBOX__', sbox_c()),
        'tundra.cpp': T_TUNDRA,
        'prowl.cpp': T_PROWL,
    }
    for name, body in files.items():
        path = os.path.join(JNI, name)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(c_header() + body)
        print('写入 %-14s %6d B' % (name, os.path.getsize(path)))

    for old in ('kkl4.cpp', 'kkl4_baseline.c', 'kkl4_crc_baseline.h'):
        p = os.path.join(JNI, old)
        if os.path.exists(p):
            os.remove(p)
            print('删除旧模块', old)
    print('ALL SOURCES OK')


if __name__ == '__main__':
    main()
